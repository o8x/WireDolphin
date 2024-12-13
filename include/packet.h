#pragma once

#include <pcap.h>
#include <string>
#include <vector>

#include "parser/arp.h"
#include "parser/ipv4.h"
#include "parser/ipv6.h"
#include "parser/tcp.h"
#include "parser/udp.h"

using namespace std;

class Packet {
    int len = 0;
    int cap_len = 0;
    int port_src = 0;
    int port_dst = 0;
    int ip_header_len = 0;
    int tcp_header_len = 0;
    int ip_version = 0;
    u_short type_flag {};
    u_char payload[2048] = {};
    pcap_pkthdr* header = nullptr;
    ipv4_header* ipv4 = nullptr;
    ipv6_header* ipv6 = nullptr;
    tcp_header* tcp = nullptr;
    arp_header* arp = nullptr;
    udp_header* udp = nullptr;
    tcp_flags* flags = nullptr;
    string time;
    timeval* time_ts = nullptr;
    string link_src;
    string link_dst;
    string host_src;
    string host_dst;
    string type;
    string info;

public:
    ~Packet();

    [[nodiscard]] int get_len() const;
    [[nodiscard]] string get_time() const;
    [[nodiscard]] string get_info() const;
    [[nodiscard]] string get_link_src() const;
    [[nodiscard]] string get_link_dst() const;
    [[nodiscard]] string get_host_src() const;
    [[nodiscard]] string get_host_dst() const;
    [[nodiscard]] string get_type() const;
    [[nodiscard]] u_short get_type_flag() const;
    [[nodiscard]] const u_char* get_payload() const;
    [[nodiscard]] ipv4_header* get_ipv4() const;
    [[nodiscard]] int get_ip_version() const;
    [[nodiscard]] ipv6_header* get_ipv6() const;
    [[nodiscard]] tcp_header* get_tcp() const;
    [[nodiscard]] tcp_flags* get_tcp_flags() const;
    [[nodiscard]] int get_ip_header_len() const;
    [[nodiscard]] int get_tcp_header_len() const;
    [[nodiscard]] int get_port_src() const;
    [[nodiscard]] int get_port_dst() const;
    [[nodiscard]] vector<int> get_color() const;
    [[nodiscard]] arp_header* get_arp() const;
    [[nodiscard]] udp_header* get_udp() const;
    [[nodiscard]] pcap_pkthdr* get_header() const;
    void set_udp(udp_header* udp);
    void set_arp(arp_header* arp);
    void set_port_src(int port_src);
    void set_port_dst(int port_dst);
    void set_ip_header_len(int ip_header_len);
    void set_tcp_header_len(int tcp_header_len);
    void set_tcp(tcp_header* tcp);
    void set_tcp_flags(tcp_flags* flags);
    void set_ipv6(ipv6_header* ipv6);
    void set_ipv4(ipv4_header* ipv4);
    void set_link_src(const string& link_src);
    void set_link_dst(const string& link_dst);
    void set_host_src(const string& addr_src);
    void set_host_dst(const string& addr_dst);
    void set_type(const string& type);
    void set_len(int len, int caplen);
    void set_info(const string& info);
    void set_header(pcap_pkthdr* hdr);
    void set_type_flag(u_short);
    void set_payload(const u_char** pkt_data);
};
