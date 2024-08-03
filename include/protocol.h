#pragma once

#include <string>
#include <sys/_types/_u_short.h>

using namespace std;

// 1个字节
typedef unsigned char u_char;

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
    u_char version_ihl;
    u_char type_of_service;
    u_short total_length;
    u_short identification;
    u_short flags_fragment;
    u_char time_to_live;
    u_char protocol;
    u_short header_checksum;
    u_char source_address[4];
    u_char dest_address[4];
    u_char options[4];
} IPV4_HEADER;

/***
*  0                      1                   2                   3
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |Version| Traffic Class |              Flow Label               |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |         Payload Length        |  Next Header  |   Hop Limit   |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* +                         Source Address                        + // 16 byte
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* +                      Destination Address                      + // 16 byte
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |                      Extension Headers                        |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct ipv6_header {
    u_char version_class_label[4]; // 4 8 20 位
    u_short payload_length;
    u_char next_header;
    u_char hop_limit;
    u_char src_host[16];
    u_char dest_host[16];
    u_char extension_header[16];
} IPV6_HEADER;
