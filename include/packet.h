#pragma once

#include <iostream>
#include <string>
#include <pcap.h>
#include "dissectors/ipv4.h"
#include "dissectors/ipv6.h"

using namespace std;

class Packet {
    long len = 0;
    u_short type_flag{};
    const u_char* payload = nullptr;
    ipv4_header* ipv4 = nullptr;
    ipv6_header* ipv6 = nullptr;
    int ip_version = 6;
    string time;
    string link_src;
    string link_dst;
    string host_src;
    string host_dst;
    string type;
    string info;

public:
    ~Packet();

    [[nodiscard]] long get_len() const;
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
    void set_ipv6(ipv6_header* const ipv6);
    void set_ipv4(ipv4_header* const ipv4);
    void set_link_src(const string& link_src);
    void set_link_dst(const string& link_dst);
    void set_host_src(const string& addr_src);
    void set_host_dst(const string& addr_dst);
    void set_type(const string& type);
    void set_len(long len);
    void set_info(const string& info);
    void set_time(const string& time);
    void set_type_flag(u_short);
    void set_payload(const u_char* payload);
};
