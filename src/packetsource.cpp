#include "packetsource.h"

#include <iostream>
#include <QDebug>
#include <QtCore/qcoreapplication.h>

#include "interface.h"
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

int PacketSource::parse_header(const pcap_pkthdr* pkt_header) const {
    return 1;
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

        if (this->parse_header(pkt_header) == 0) {
            continue;
        }

        Packet packet;
        packet.set_len(pkt_header->len);
        packet.set_caplen(pkt_header->caplen);
        packet.set_time(format_timeval_to_string(pkt_header->ts));

        emit this->accepted(packet);
    }

    emit this->listen_stopped(name, "off");
}
