#pragma once

#include "packet.h"
#include <QThread>
#include <pcap.h>

class PacketSource final : public QThread {
    Q_OBJECT

    vector<Packet*>* packetsPtr;
    pcap_t* interface = nullptr;
    pcap_if_t* device = nullptr;
    string filename;
    bool running = false;
    void run() override;
    static int parse_header(const u_char**, Packet*& p);

signals:
    void listen_started(std::string name, std::string message) const;
    void listen_stopped(std::string name, std::string message) const;
    void packet_pushed(size_t);

public:
    explicit PacketSource(QObject* parent = nullptr, vector<Packet*>* packets = nullptr)
        : QThread(parent)
        , packetsPtr(packets)
    {
    }

    void init(pcap_if_t* device, pcap_t* interface);
    [[nodiscard]] string get_filename() const;
    void set_filename(const string& filename);
    [[nodiscard]] pcap_t* get_interface() const;
    void free();
};
