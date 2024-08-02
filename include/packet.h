#pragma once

#include <iostream>
#include <string>
#include <pcap.h>
using namespace std;

class Packet {
    long len = 0;
    u_short type_flag{};
    const u_char* payload = nullptr;
    string time;
    string link_src;
    string link_dst;
    string addr_src;
    string addr_dst;
    string type;
    string info;

public:
    [[nodiscard]] long get_len() const;
    [[nodiscard]] string get_time() const;
    [[nodiscard]] string get_info() const;
    [[nodiscard]] string get_link_src() const;
    [[nodiscard]] string get_link_dst() const;
    [[nodiscard]] string get_addr_src() const;
    [[nodiscard]] string get_addr_dst() const;
    [[nodiscard]] string get_type() const;
    [[nodiscard]] u_short get_type_flag() const;
    [[nodiscard]] const u_char* get_payload() const;

    void set_link_src(const string& link_src);
    void set_link_dst(const string& link_dst);
    void set_addr_src(const string& addr_src);
    void set_addr_dst(const string& addr_dst);
    void set_type(const string& type);
    void set_len(long len);
    void set_info(const string& info);
    void set_time(const string& time);
    void set_type_flag(u_short);
    void set_payload(const u_char* payload);
};
