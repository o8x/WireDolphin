#include "packet.h"
#include <iostream>

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

string Packet::get_addr_src() const {
    return addr_src;
}

void Packet::set_addr_src(const string& addr_src) {
    this->addr_src = addr_src;
}

string Packet::get_addr_dst() const {
    return addr_dst;
}

void Packet::set_addr_dst(const string& addr_dst) {
    this->addr_dst = addr_dst;
}

string Packet::get_protocol() const {
    return protocol;
}

u_short Packet::get_protocol_flag() const {
    return protocol_flag;
}

void Packet::set_protocol(const string& protocol) {
    this->protocol = protocol;
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

void Packet::set_protocol_flag(u_short flag) {
    this->protocol_flag = flag;
}

[[nodiscard]] const u_char* Packet::get_payload() const {
    return payload;
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
