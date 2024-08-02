#pragma once

#include <string>
#include <sys/_types/_u_short.h>

using namespace std;

// 1个字节
typedef uchar u_char;

// 2个字节
typedef ushort u_short;

// 4个字节
typedef uint u_int;

/**
* +-----------+-----------+-------------+--------------------+----------+
* |   DMAC    |   SMAC    |     Type    |          Data      |   FCS    |
* |  6 Bytes  |  6 Bytes  |   2 Bytes   |  Variable length   | 4 Bytes  |
* +-----------+-----------+-------------+--------------------+----------+
* FCS 不需要处理
*/
typedef struct ethernet_header {
    u_char link_src[6];
    u_char link_dst[6];
    u_short type;
} ETHERNET_HEADER;

/**
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |     1byte     |     1byte     |           2byte               |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |Version|  IHL  |Type of Service|          Total Length         |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |         Identification        |Flags|      Fragment Offset    |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |  Time to Live |    Protocol   |         Header Checksum       |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |                       Source Address                          |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |                    Destination Address                        |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |                    Options                    |    Padding    |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct ipv4_header {
    u_char version;
    u_char type;
    u_short length;
    u_short identifier;
    u_short fragment_offset;
    u_char TTL;
    u_char protocol;
    u_short checksum;
    u_char src_addr[4];
    u_char dst_addr[4];
    u_char options[4];
} IPV4_HEADER;
