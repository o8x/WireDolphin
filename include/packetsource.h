#pragma once

#include "packet.h"
#include <QThread>
#include <pcap.h>

typedef struct packetsource_state {
    string interface_name;
    string state;
    string dump_filename;
} PACKETSOURCE_STATE;

class PacketSource final : public QThread {
    Q_OBJECT

    vector<Packet*>* packetsPtr;
    pcap_t* interface = nullptr;
    pcap_if_t* device = nullptr;
    string dump_filename;
    pcap_dumper_t* dump_handler = nullptr;
    string filename;
    bool running = false;
    void run() override;
    void dump_flush(const pcap_pkthdr*, const u_char*) const;
    static int parse_header(const u_char**, Packet*& p);

signals:
    void listen_started(PACKETSOURCE_STATE) const;
    void listen_stopped(PACKETSOURCE_STATE) const;
    void captured(size_t, Packet*);

public:
    explicit PacketSource(QObject* parent = nullptr, vector<Packet*>* packets = nullptr)
        : QThread(parent)
        , packetsPtr(packets)
    {
    }

    ~PacketSource();

    void clean_last_dump();
    void init(pcap_if_t* device, pcap_t* interface);
    [[nodiscard]] string get_filename() const;
    void set_filename(const string& filename);
    [[nodiscard]] pcap_t* get_interface() const;
    [[nodiscard]] string get_dump_filename() const;
    void free();
};
