#pragma once

#include <string>
#include <pcap.h>
using namespace std;

class Packet {
    long len = 0;
    const u_char* payload = nullptr;
    string time;
    string link_src;
    string link_dst;
    string addr_src;
    string addr_dst;
    string protocol;
    string info;
    u_short protocol_flag;

public:
    [[nodiscard]] long get_len() const;
    [[nodiscard]] string get_time() const;
    [[nodiscard]] string get_info() const;
    [[nodiscard]] string get_link_src() const;
    [[nodiscard]] string get_link_dst() const;
    [[nodiscard]] string get_addr_src() const;
    [[nodiscard]] string get_addr_dst() const;
    [[nodiscard]] string get_protocol() const;
    [[nodiscard]] u_short get_protocol_flag() const;
    [[nodiscard]] const u_char* get_payload() const;

    void set_link_src(const string& link_src);
    void set_link_dst(const string& link_dst);
    void set_addr_src(const string& addr_src);
    void set_addr_dst(const string& addr_dst);
    void set_protocol(const string& protocol);
    void set_len(long len);
    void set_info(const string& info);
    void set_time(const string& time);
    void set_protocol_flag(u_short);
    void set_payload(const u_char** payload, int size);
};
