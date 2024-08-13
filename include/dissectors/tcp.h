#pragma once

#include <iostream>
using namespace std;
/**
 * 0               1                           2                   3
 * +-------------------------------+-------------------------------+
 * |          Source Port          |       Destination Port        |
 * +-------------------------------+-------------------------------+
 * |                        Sequence Number                        |
 * +---------------------------------------------------------------+
 * |                    Acknowledgment Number                      |
 * +-------+-------+-+-+-+-+-+-+-+-+-------------------------------+
 * |  Data |       |C|E|U|A|P|R|S|F|                               |
 * | Offset|Rsved  |W|C|R|C|S|S|Y|I|            Window             |
 * |       |       |R|E|G|K|H|T|N|N|                               |
 * +-------+-----------+-+-+-+-+-+-+-------------------------------+
 * |           Checksum            |         Urgent Pointer        |
 * +-------------------------------+-------------------------------+
 * |                            Options                            |
 * +---------------------------------------------------------------+
 * |                             data                              |
 * +---------------------------------------------------------------+
 */
typedef struct tcp_header {
    u_short src_port;
    u_short dst_port;
    u_int seq_number;
    u_int ack_number;
    // 数据偏移，指出TCP报文段的数据起始处距离TCP报文段的起始处有多远
    // 最多有60字节的首部，若无选项字段，正常为20字节
    u_char data_offset;
    u_char flags; // index: 0CWR 1ECE 2URG 3ACK 4PSH 5RST 6SYN 7FIN
    u_short window;
    u_short checksum;
    u_short urgent;
    u_short options;
} TCP_HEADER;

typedef struct tcp_flags {
    bool CWR;
    bool ECE;
    bool URG;
    bool ACK;
    bool PSH;
    bool RST;
    bool SYN;
    bool FIN;
} TCP_FLAGS;

void parse_tcp_flags(tcp_flags* dst, u_char flags);
