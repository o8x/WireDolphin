#include <iostream>
#include <QDebug>
#include <QtCore/qcoreapplication.h>
#include "interface.h"
#include "dissectors/ethernet.h"
#include "dissectors/ipv4.h"
#include "dissectors/ipv6.h"
#include "packetsource.h"
#include "utils.h"
#include "dissectors/arp.h"
#include "dissectors/tcp.h"
#include "dissectors/udp.h"

using namespace std;

void PacketSource::init(pcap_if_t* device, pcap_t* interface) {
    this->device = device;
    this->interface = interface;
    this->running = true;
}

string PacketSource::get_filename() const {
    return filename;
}

void PacketSource::set_filename(const string& filename) {
    this->filename = filename;
}

pcap_t* PacketSource::get_interface() const {
    return interface;
}

void PacketSource::free() {
    this->running = false;

    if (this->interface != nullptr) {
        pcap_close(this->interface);
        this->interface = nullptr;
    }

    if (this->device != nullptr) {
        this->device = nullptr;
    }
}

void PacketSource::run() {
    const string name = this->device ? this->device->name : this->filename;

    emit listen_started(name, "on");
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

        p->set_time(format_timeval_to_string(pkt_header->ts));
        p->set_payload(pkt_data);

        packetsPtr->push_back(p);
        // 如果并发，会有线程安全问题，size 不准
        emit this->packet_pushed(packetsPtr->size() - 1);
    }

    emit this->listen_stopped(name, "off");
}

int PacketSource::parse_header(const u_char** pkt_data, Packet*& p) {
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
                info.append("PSH ").
                     append(to_string(p->get_len() - 14 - p->get_ip_header_len() - p->get_tcp_header_len())).
                     append("byte ");
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
            info.append(bytes_to_string(arp->sender_ethernet, 6, ":"));
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
