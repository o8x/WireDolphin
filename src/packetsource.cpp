#include "packetsource.h"

#include <iostream>
#include <QDebug>
#include <QtCore/qcoreapplication.h>

#include "interface.h"
#include "protocol.h"
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

        p->set_time(format_timeval_to_string(pkt_header->ts));
        p->set_payload(pkt_data);

        packetsPtr->push_back(p);
        // 如果并发，会有线程安全问题，size 不准
        emit this->packet_pushed(packetsPtr->size() - 1);
    }

    emit this->listen_stopped(name, "off");
}

string PacketSource::byte_to_string(u_char* byte, int size) {
    std::ostringstream oss;
    for (int i = 0; i < size; i++) {
        oss << std::hex << ntohs(byte[i]);
        if (i != size - 1) {
            oss << ":";
        }
    }

    return oss.str();
}

int PacketSource::parse_header(const u_char** pkt_data, Packet*& p) {
    ethernet_header* eth = (ETHERNET_HEADER*)*pkt_data;

    p->set_link_src(byte_to_string(eth->link_src, 6));
    p->set_link_dst(byte_to_string(eth->link_dst, 6));
    // p->set_info(byte_to_string(eth->link_src, 6).append(" -> ").append(byte_to_string(eth->link_dst, 6)));

    u_short type = ntohs(eth->type);
    switch (type) {
    case 0x0800:
        p->set_protocol("IPv4");
        p->set_protocol_flag(0x0800);
        return 1;
    case 0x0806:
        p->set_protocol("ARP");
        p->set_protocol_flag(0x0806);
        return 1;
    case 0x0808:
        p->set_protocol("IARP");
        p->set_protocol_flag(0x0808);
        return 1;
    case 0x8035:
        p->set_protocol("RARP");
        p->set_protocol_flag(0x8035);
        return 1;
    case 0x8100:
        p->set_protocol("VLAN C-Tag");
        p->set_protocol_flag(0x8100);
        return 1;
    case 0x814C:
        p->set_protocol("SNMPoE");
        p->set_protocol_flag(0x814C);
        return 1;
    case 0x86DD:
        p->set_protocol("IPv6");
        p->set_protocol_flag(0x86DD);
        return 1;
    case 0x876B:
        p->set_protocol("TCP/IP");
        p->set_protocol_flag(0x876B);
        return 1;
    case 0x8808:
        p->set_protocol("EPON");
        p->set_protocol_flag(0x8808);
        return 1;
    case 0x880B:
        p->set_protocol("PPP");
        p->set_protocol_flag(0x880B);
        return 1;
    case 0x8863:
        p->set_protocol("PPPoE Discovery");
        p->set_protocol_flag(0x8863);
        return 1;
    case 0x8864:
        p->set_protocol("PPPoE Session");
        p->set_protocol_flag(0x8864);
        return 1;
    case 0x88A8:
        p->set_protocol("VLAN S-Tag");
        p->set_protocol_flag(0x88A8);
        return 1;
    case 0x88CC:
        p->set_protocol("LLDP");
        p->set_protocol_flag(0x88CC);
        return 1;
    }

    p->set_protocol("");
    p->set_protocol_flag(type);
    return 0;
}
