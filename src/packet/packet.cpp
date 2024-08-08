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

void Packet::set_len(const int len, const int caplen) {
    this->len = len;
    this->cap_len = caplen;
}

[[nodiscard]] int Packet::get_len() const {
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

tcp_header* Packet::get_tcp() const {
    return tcp;
}

void Packet::set_tcp(tcp_header* const tcp) {
    this->tcp = tcp;
}

tcp_flags* Packet::get_tcp_flags() const {
    return flags;
}

void Packet::set_tcp_flags(tcp_flags* const flags) {
    this->flags = flags;
}

void Packet::set_ipv6(ipv6_header* const ipv6) {
    this->ipv6 = ipv6;
    this->ip_version = 6;
}

void Packet::set_ipv4(ipv4_header* const ipv4) {
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

int Packet::get_ip_header_len() const {
    return ip_header_len;
}

void Packet::set_ip_header_len(const int ip_header_len) {
    this->ip_header_len = ip_header_len;
}

int Packet::get_tcp_header_len() const {
    return tcp_header_len;
}

int Packet::get_port_src() const {
    return port_src;
}

void Packet::set_port_src(const int port_src) {
    this->port_src = port_src;
}

int Packet::get_port_dst() const {
    return port_dst;
}

vector<int> Packet::get_color() const {
    // ARP
    if (this->get_type_flag() == 0x0806) {
        return {250, 240, 215};
    }

    if (this->udp != nullptr) {
        return {218, 238, 255};
    }

    if (this->type == "HTTP") {
        return {0, 250, 154};
    }

    if (this->flags != nullptr) {
        /**
         * 三次握手
         * 第一次握手（SYN）：浅天蓝色， 客户端发送SYN请求，表示希望建立连接
         * 第二次握手（SYN-ACK）：天蓝色， 服务器收到SYN后，回应SYN-ACK表示同意连接
         * 第三次握手（ACK）：深天蓝色， 客户端收到SYN-ACK后，发送ACK确认，连接建立
         */
        if (this->flags->SYN && !this->flags->ACK) {
            return {135, 206, 250};
        }

        if (this->flags->SYN && this->flags->ACK) {
            return {135, 206, 235};
        }

        // 挥手的两次也会被它捕获
        // 挥手需要重组流才能正确识别挥手过程
        if (this->flags->ACK && this->tcp->ack_number == 1) {
            return {0, 191, 255};
        }

        /*
         * 第一次挥手（FIN）：橙子， 客户端发送FIN请求，表示希望终止连接
         * 第二次挥手（ACK）：玫瑰， 服务器收到FIN后，发送ACK确认
         * 第三次挥手（FIN）：深橙色， 服务器也发送FIN请求，表示同意终止连接
         * 第四次挥手（ACK）：金色，客户端收到FIN后，发送ACK确认，连接终止
         */
        if (this->flags->FIN) {
            return {255, 165, 0};
        }

        /*
        * SYN（同步）：天蓝，用于建立连接的初始请求
        * ACK（确认）：粉蓝色，用于确认收到的数据包
        * FIN（终止）：红色，用于终止连接的请求
        * RST（复位）：番茄，用于重置连接
        * PSH（推送）：浅青色，用于提示接收方将数据立即提交给应用程序
        * URG（紧急）：黄色，用于标记紧急数据
        */
        if (this->flags->PSH) {
            return {224, 255, 255};
        }

        if (this->flags->RST) {
            return {255, 99, 71};
        }

        if (this->flags->URG) {
            return {255, 255, 0};
        }

        if (this->flags->ACK) {
            return {176, 224, 230};
        }

        /*
         * 乱序丢包重传
         * 乱序：棕色，数据包按错序接收，需要重组
         * 丢包：灰色，数据包在传输过程中丢失
         * 重传：黑色，丢失或损坏的数据包需要重新发送
         */
    }

    return {255, 255, 255};
}

arp_header* Packet::get_arp() const {
    return arp;
}

udp_header* Packet::get_udp() const {
    return udp;
}

void Packet::set_udp(udp_header* const udp) {
    this->udp = udp;
}

void Packet::set_arp(arp_header* const arp) {
    this->arp = arp;
}

void Packet::set_port_dst(const int port_dst) {
    this->port_dst = port_dst;
}

void Packet::set_tcp_header_len(const int tcp_header_len) {
    this->tcp_header_len = tcp_header_len;
}

Packet::~Packet() {
    delete ipv4;
    delete ipv6;
    delete tcp;
    delete flags;
    delete arp;
    delete udp;
}
