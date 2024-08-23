#pragma once

#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_UNREACHABLE 3
#define ICMP_TYPE_SOURCE_CLOSED 4
#include <iostream>

using namespace std;

/**
 * +0------7-------15---------------31
 * |  Type | Code  |    Checksum    |
 * +--------------------------------+
 * |          Message Body          |
 * |        (Variable length)       |
 * +--------------------------------+
 */
typedef struct icmp_header {
    u_char type;
    u_char code;
} ICMP_HEADER;

// Echo Request/Reply
typedef struct icmp_echo {
    icmp_header icmp_header;
    u_char identifier[2];
    u_char seq_number[2];
    // char data[1500]; // 数据不定长，但不会超过MTU
} ICMP_ECHO;
