#pragma once

#include <string>
#include <iostream>

/**
 *0                 2                 3
 *+-----------------+-----------------+
 *| Source Port     |Destination Port |
 *+-----------------+-----------------+
 *|     Length      |    Checksum     |
 *+-----------------+-----------------+
 *|               data                |
 *+-----------------------------------+
 */
typedef struct udp_header {
    u_short src_port;
    u_short dst_port;
    u_short total_length;
    u_short checksum;
} UDP_HEADER;
