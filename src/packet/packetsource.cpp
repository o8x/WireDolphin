#include <iostream>
#include <QDebug>
#include <QtCore/qcoreapplication.h>
#include "interface.h"
#include "dissectors/ethernet.h"
#include "dissectors/ipv4.h"
#include "dissectors/ipv6.h"
#include "packetsource.h"
#include "utils.h"

using namespace std;

void PacketSource::init(pcap_if_t* device, pcap_t* interface) {
    this->device = device;
    this->interface = interface;
    this->running = true;
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
    const string name = this->device->name;

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
        if (parse_header(&pkt_data, p) == 0) {
            continue;
        }

        p->set_len(pkt_header->len);
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

        // IPv4 长度，即以太网载荷长度
        ipv4->total_length = ntohs(ipv4->total_length);
        ipv4->header_checksum = ntohs(ipv4->header_checksum);
        ipv4->identification = ntohs(ipv4->identification);

        p->set_ipv4(ipv4);
        p->set_host_src(string(to_string(int(ipv4->source_address[0]))).
                        append(".").
                        append(to_string(int(ipv4->source_address[1]))).append(".").
                        append(to_string(int(ipv4->source_address[2]))).append(".").
                        append(to_string(int(ipv4->source_address[3]))));
        p->set_host_dst(string(to_string(int(ipv4->dest_address[0]))).
                        append(".").
                        append(to_string(int(ipv4->dest_address[1]))).append(".").
                        append(to_string(int(ipv4->dest_address[2]))).append(".").
                        append(to_string(int(ipv4->dest_address[3]))));

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
        case 6:
            p->set_type("TCP");
            break;
        case 17:
            p->set_type("UDP");
            break;
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
    case 0x0806:
        p->set_type("ARP");
        p->set_type_flag(0x0806);
        return 1;
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
