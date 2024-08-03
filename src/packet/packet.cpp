#include <iostream>
#include "packet.h"

string Packet::get_link_src() const {
    return link_src;
}

void Packet::set_link_src(const string& link_src) {
    this->link_src = link_src;
}

string Packet::get_link_dst() const {
    return link_dst;
}

void Packet::set_link_dst(const string& link_dst) {
    this->link_dst = link_dst;
}

string Packet::get_host_src() const {
    return host_src;
}

void Packet::set_host_src(const string& host_src) {
    this->host_src = host_src;
}

string Packet::get_host_dst() const {
    return host_dst;
}

void Packet::set_host_dst(const string& host_dst) {
    this->host_dst = host_dst;
}

string Packet::get_type() const {
    return type;
}

u_short Packet::get_type_flag() const {
    return type_flag;
}

void Packet::set_type(const string& type) {
    this->type = type;
}

void Packet::set_len(const long len) {
    this->len = len;
}

[[nodiscard]] long Packet::get_len() const {
    return len;
}

[[nodiscard]] string Packet::get_time() const {
    return time;
}

void Packet::set_time(const string& time) {
    this->time = time;
}

void Packet::set_type_flag(u_short flag) {
    this->type_flag = flag;
}

[[nodiscard]] const u_char* Packet::get_payload() const {
    return payload;
}

ipv4_header* Packet::get_ipv4() const {
    return ipv4;
}

int Packet::get_ip_version() const {
    return ip_version;
}

ipv6_header* Packet::get_ipv6() const {
    return ipv6;
}

void Packet::set_ipv6(ipv6_header * const ipv6) {
    this->ipv6 = ipv6;
    this->ip_version = 6;
}

void Packet::set_ipv4(ipv4_header * const ipv4) {
    this->ipv4 = ipv4;
    this->ip_version = 4;
}

string Packet::get_info() const {
    return info;
}

void Packet::set_info(const string& info) {
    this->info = info;
}

void Packet::set_payload(const u_char* payload) {
    this->payload = payload;
}

Packet::~Packet() {
    delete ipv4;
    delete ipv6;
}
