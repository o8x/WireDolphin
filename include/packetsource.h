#pragma once

#include <QThread>
#include <pcap.h>

#include "packet.h"

class PacketSource final : public QThread {
    Q_OBJECT

    pcap_t* interface = nullptr;
    pcap_if_t* device = nullptr;
    bool running = false;
    void run() override;
    static string byte_to_string(u_char* byte, int size);
    static int parse_header(const u_char**, Packet& p);

signals:
    void listen_started(std::string name, std::string message) const;
    void listen_stopped(std::string name, std::string message) const;
    void accepted(Packet);

public:
    explicit PacketSource(QObject* parent = nullptr) : QThread(parent) {
    }

    void init(pcap_if_t* device, pcap_t* interface);
    [[nodiscard]] pcap_t* get_interface() const;
    void free();
};
