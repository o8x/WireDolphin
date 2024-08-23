#include "packetsource.h"
#include "dissectors/arp.h"
#include "dissectors/ethernet.h"
#include "dissectors/ipv4.h"
#include "dissectors/ipv6.h"
#include "dissectors/tcp.h"
#include "dissectors/udp.h"
#include "interface.h"
#include "utils.h"
#include <QtCore/qcoreapplication.h>
#include <__filesystem/operations.h>
#include <glog/logging.h>
#include <iostream>

using namespace std;

PacketSource::~PacketSource()
{
    free_history();
}

PacketSource::PacketSource()
{
    bridge = std::queue<Packet*>();
    history = std::vector<Packet*>();
    last_access = std::chrono::steady_clock::now();
}

void PacketSource::start_on_interface(pcap_if_t* device, pcap_t* interface)
{
    this->device = device;
    this->interface = interface;
    this->running = true;

    free_history();

    if (device != nullptr) {
        dump_filename = std::format("/tmp/{}.{}.pcap", device->name, std::time(0));
    } else {
        dump_filename = std::format("/tmp/{}.pcap", std::time(0));
    }

    LOG(INFO) << std::format("open dump handler, filename: {}", dump_filename);
    this->dump_handler = pcap_dump_open(interface, dump_filename.c_str());

    fill_thread = std::thread([this]() {
        this->capture_packet();
    });

    consume_thread = std::thread([this]() {
        this->consume_queue();
    });
}

size_t PacketSource::packet_count() const
{
    return history.size();
}

Packet* PacketSource::peek(int index) const
{
    return history[index];
}

void PacketSource::free_wait()
{
    this->running = false;

    if (this->interface != nullptr) {
        pcap_close(this->interface);
        this->interface = nullptr;
    }

    if (this->device != nullptr) {
        this->device = nullptr;
    }

    if (this->dump_handler != nullptr) {
        pcap_dump_close(this->dump_handler);
        this->dump_handler = nullptr;
    }

    if (fill_thread.joinable()) {
        fill_thread.join();
    }

    if (consume_thread.joinable()) {
        consume_thread.join();
    }
}

void PacketSource::consume_queue()
{
    while (running) {
        auto now = std::chrono::steady_clock::now();

        // 获取锁
        std::unique_lock l(mtx);

        // 桥中没有数据 || 数据量小于平均数
        if (const size_t size = bridge.size(); size == 0 || size < period_average) {
            continue;
        }

        // 数据不够，并且也不到指定的更新周期
        if (now - last_access < std::chrono::milliseconds(DEFAULT_QUEUE_UPDATE_TIMEOUT_MS)) {
            continue;
        }

        // 复制队列的全部值
        std::queue<Packet*> q_copy = std::move(bridge);
        // 释放队列内存，可能不需要，因为 WAIT_QUEUE_MS 周期内不一定能占用多大内存
        std::queue<Packet*>().swap(bridge);
        l.unlock();

        last_access = now;
        period_average = AVERAGE_PERIOD(q_copy.size() / DEFAULT_QUEUE_UPDATE_TIMEOUT_MS);

        // 锁已经被自动释放了
        // 此时消费复制的值，将不会持有锁
        for (; !q_copy.empty(); q_copy.pop()) {
            auto p = q_copy.front();
            history.push_back(p);

            emit this->captured(history.size() - 1, p);
            dump_flush(p->get_header(), p->get_payload());
        }
    }
}

string PacketSource::get_dump_filename() const
{
    return dump_filename;
}

string PacketSource::get_filename() const
{
    return filename;
}

void PacketSource::set_filename(const string& filename)
{
    this->filename = filename;
}

pcap_t* PacketSource::get_interface() const
{
    return interface;
}

/**
 * 清空队列与历史捕获包
 */
void PacketSource::free_history()
{
    // 获取锁
    std::unique_lock l(mtx);

    // 清空历史捕获的包和占用的内存
    ranges::for_each(history, [](Packet* p) {
        delete p;
    });

    for (; !bridge.empty(); bridge.pop()) {
        delete bridge.front();
    }

    vector<Packet*>().swap(history);
    std::queue<Packet*>().swap(bridge);

    // 清空捕获文件的名称
    if (this->dump_filename.empty()) {
        return;
    }

    std::filesystem::remove(this->dump_filename);
    LOG(INFO) << std::format("remove {}", this->dump_filename);
    this->dump_filename = "";
}

void PacketSource::capture_packet()
{
    const string name = this->device ? this->device->name : this->filename;

    emit listen_started({ .dump_filename = dump_filename,
        .interface_name = name,
        .state = "on" });

    while (true) {
        if (!running || this->interface == nullptr) {
            break;
        }

        pcap_pkthdr* pkt_header;
        const u_char* pkt_data;

        if (pcap_next_ex(this->interface, &pkt_header, &pkt_data) != 1) {
            continue;
        }

        auto* p = new Packet;
        p->set_len(int(pkt_header->len), int(pkt_header->caplen));
        if (parse_header(&pkt_data, p) == 0) {
            continue;
        }

        p->set_header(pkt_header);
        p->set_payload(&pkt_data);

        std::unique_lock l(mtx);
        bridge.push(p);
    }

    emit listen_stopped({ .dump_filename = dump_filename,
        .interface_name = name,
        .state = "off" });
}

void PacketSource::dump_flush(const pcap_pkthdr* h, const u_char* sp) const
{
    if (dump_handler == nullptr) {
        return;
    }

    pcap_dump(reinterpret_cast<u_char*>(dump_handler), h, sp);
    pcap_dump_flush(dump_handler);
}

int PacketSource::parse_header(const u_char** pkt_data, Packet*& p)
{
    ethernet_header* eth = (ETHERNET_HEADER*)*pkt_data;

    p->set_link_src(bytes_to_ascii(eth->link_src, 6, ":"));
    p->set_link_dst(bytes_to_ascii(eth->link_dst, 6, ":"));

    u_short type = ntohs(eth->type);
    switch (type) {
    case 0x0800: {
        p->set_type("IPv4");
        p->set_type_flag(0x0800);

        // 放入堆中，避免被回收
        ipv4_header* ipv4 = new IPV4_HEADER;
        memcpy(ipv4, *pkt_data + sizeof(ethernet_header), sizeof(ipv4_header));

        ipv4->total_length = ntohs(ipv4->total_length);
        ipv4->header_checksum = ntohs(ipv4->header_checksum);
        ipv4->identification = ntohs(ipv4->identification);

        p->set_ipv4(ipv4);
        p->set_ip_header_len((ipv4->version_ihl & 0xfl) * 4);
        p->set_host_src(bytes_to_ip(ipv4->source_address));
        p->set_host_dst(bytes_to_ip(ipv4->dest_address));

        switch (ipv4->protocol) {
        case 0:
            p->set_type("-");
            break;
        case 1:
            p->set_type("ICMP");
            break;
        case 2:
            p->set_type("IGMP");
            break;
        case 3:
            p->set_type("GGP");
            break;
        case 4:
            p->set_type("IP in IP");
            break;
        case 6: {
            p->set_type("TCP");
            tcp_header* tcp = new TCP_HEADER;
            memcpy(tcp, *pkt_data + sizeof(ethernet_header) + p->get_ip_header_len(), sizeof(tcp_header));
            auto* flags = new TCP_FLAGS;
            parse_tcp_flags(flags, tcp->flags);
            tcp->src_port = ntohs(tcp->src_port);
            tcp->dst_port = ntohs(tcp->dst_port);

            p->set_tcp_header_len((tcp->data_offset >> 4) * 4);
            p->set_port_src(tcp->src_port);
            p->set_port_dst(tcp->dst_port);
            p->set_tcp_flags(flags);
            p->set_tcp(tcp);

            string info = p->get_info();

            int layer4_offset = 14 + p->get_ip_header_len() + p->get_tcp_header_len();
            std::istringstream stream(reinterpret_cast<const char*>(*pkt_data + layer4_offset));
            if (string method = is_restful_request(stream); !method.empty()) {
                stream.seekg(0, std::ios::beg);
                std::string line;
                if (std::getline(stream, line)) {
                    // 去掉 \r
                    info.append(line);
                }

                p->set_type("HTTP");
                p->set_info(info);
                break;
            }

            info.append("Seq ").append(to_string(tcp->seq_number)).append(" ");
            if (flags->URG) {
                info.append("URG,");
            }

            if (flags->ACK) {
                info.append("Ack ").append(to_string(tcp->ack_number)).append(" ");
            }

            if (flags->PSH) {
                auto len = to_string(p->get_len() - 14 - p->get_ip_header_len() - p->get_tcp_header_len());
                info.append("PSH ").append(len).append("byte ");
            }

            if (flags->RST) {
                info.append("RST,");
            }

            if (flags->SYN) {
                info.append("SYN,");
            }

            if (flags->FIN) {
                info.append("FIN,");
            }

            p->set_info(info.substr(0, info.length() - 1));
            break;
        }
        case 17: {
            p->set_type("UDP");
            udp_header* udp = new UDP_HEADER;
            memcpy(udp, *pkt_data + sizeof(ethernet_header) + p->get_ip_header_len(), sizeof(udp_header));
            udp->src_port = ntohs(udp->src_port);
            udp->dst_port = ntohs(udp->dst_port);

            p->set_port_src(udp->src_port);
            p->set_port_dst(udp->dst_port);
            p->set_udp(udp);

            break;
        }
        case 20:
            p->set_type("HMP");
            break;
        case 27:
            p->set_type("RDP");
            break;
        case 46:
            p->set_type("RSVP");
            break;
        case 47:
            p->set_type("GRE");
            break;
        case 50:
            p->set_type("ESP");
            break;
        case 51:
            p->set_type("AH");
            break;
        case 54:
            p->set_type("NARP");
            break;
        case 58:
            p->set_type("IPv6-ICMP");
            break;
        case 59:
            p->set_type("IPv6-NoNxt");
            break;
        case 60:
            p->set_type("IPv6-Opts");
            break;
        case 89:
            p->set_type("OSPF");
            break;
        case 112:
            p->set_type("VRRP");
            break;
        case 115:
            p->set_type("L2TP");
            break;
        case 124:
            p->set_type("ISIS");
            break;
        case 126:
            p->set_type("CRTP");
            break;
        case 127:
            p->set_type("CRUDP");
            break;
        case 132:
            p->set_type("SCTP");
            break;
        case 136:
            p->set_type("UDPLite");
            break;
        case 137:
            p->set_type("MPLS-in-IP");
            break;
        }

        return 1;
    }
    case 0x0806: {
        p->set_type("ARP");
        p->set_type_flag(0x0806);

        arp_header* arp = new ARP_HEADER;
        memcpy(arp, *pkt_data + sizeof(ethernet_header), sizeof(arp_header));

        arp->protocol_type = ntohs(arp->protocol_type);
        arp->hardware_type = ntohs(arp->hardware_type);
        arp->op = ntohs(arp->op);
        p->set_arp(arp);
        p->set_host_src(bytes_to_ip(arp->sender_host));
        p->set_host_dst(bytes_to_ip(arp->destination_host));

        string info = p->get_info();
        switch (arp->op) {
        case 1:
            info.append("Broadcast Ask ");
            info.append(bytes_to_ip(arp->destination_host));
            info.append(", from ");
            info.append(bytes_to_ip(arp->sender_host));
            info.append("(");
            info.append(p->get_link_src());
            info.append(")");
            break;
        case 2:
            info.append("Answer ");
            info.append(p->get_link_src());
            info.append(", from ");
            info.append(bytes_to_ascii(arp->sender_ethernet, 6, ":"));
            info.append("(");
            info.append(bytes_to_ip(arp->sender_host));
            info.append(")");
            break;
        case 3:
            p->set_type("RARP");
            info = info.append("Reply");
            break;
        case 4:
            p->set_type("RARP");
            info = info.append("Reply");
            break;
        }

        p->set_info(info);
        return 1;
    }
    case 0x0808:
        p->set_type("IARP");
        p->set_type_flag(0x0808);
        return 1;
    case 0x8035:
        p->set_type("RARP");
        p->set_type_flag(0x8035);
        return 1;
    case 0x8100:
        p->set_type("VLAN C-Tag");
        p->set_type_flag(0x8100);
        return 1;
    case 0x814C:
        p->set_type("SNMPoE");
        p->set_type_flag(0x814C);
        return 1;
    case 0x86DD: {
        p->set_type("IPv6");
        p->set_type_flag(0x86DD);

        ipv6_header* ipv6 = new IPV6_HEADER;
        memcpy(ipv6, *pkt_data + sizeof(ethernet_header), sizeof(ipv6_header));

        ipv6->payload_length = ntohs(ipv6->payload_length);
        p->set_ipv6(ipv6);
        p->set_host_src(bytes_to_string(ipv6->src_host, 16, ":"));
        p->set_host_dst(bytes_to_string(ipv6->dest_host, 16, ":"));

        switch (ipv6->next_header) {
        case 0:
            p->set_type("Hop-by-Hop");
            break;
        case 1:
            p->set_type("ICMP6");
            break;
        case 2:
            p->set_type("IGMP6");
            break;
        case 3:
            p->set_type("GGP6");
            break;
        case 4:
            p->set_type("IPv4e");
            break;
        case 5:
            p->set_type("Stream");
            break;
        case 6:
            p->set_type("TCP6");
            break;
        case 7:
            p->set_type("CBT");
            break;
        case 8:
            p->set_type("EGP");
            break;
        case 9:
            p->set_type("IGP");
            break;
        case 10:
            p->set_type("BBN");
            break;
        case 11:
            p->set_type("NVP");
            break;
        case 12:
            p->set_type("PUP");
            break;
        case 13:
            p->set_type("ARGUS");
            break;
        case 14:
            p->set_type("EMCON");
            break;
        case 15:
            p->set_type("XNET");
            break;
        case 16:
            p->set_type("CHAOS");
            break;
        case 17:
            p->set_type("UDP6");
            break;
        case 18:
            p->set_type("MUX");
            break;
        case 19:
            p->set_type("DC-MEAS");
            break;
        case 20:
            p->set_type("HMP");
            break;
        case 21:
            p->set_type("PRM");
            break;
        }

        return 1;
    }
    case 0x876B:
        p->set_type("TCP/IP");
        p->set_type_flag(0x876B);
        return 1;
    case 0x8808:
        p->set_type("EPON");
        p->set_type_flag(0x8808);
        return 1;
    case 0x880B:
        p->set_type("PPP");
        p->set_type_flag(0x880B);
        return 1;
    case 0x8863:
        p->set_type("PPPoE Discovery");
        p->set_type_flag(0x8863);
        return 1;
    case 0x8864:
        p->set_type("PPPoE Session");
        p->set_type_flag(0x8864);
        return 1;
    case 0x88A8:
        p->set_type("VLAN S-Tag");
        p->set_type_flag(0x88A8);
        return 1;
    case 0x88CC:
        p->set_type("LLDP");
        p->set_type_flag(0x88CC);
        return 1;
    }

    p->set_type("");
    p->set_type_flag(type);
    return 0;
}
