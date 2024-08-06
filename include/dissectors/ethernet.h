#pragma once
#include <iostream>

/**
* +-----------+-----------+-------------+--------------------+----------+
* |   DMAC    |   SMAC    |     Type    |          Data      |   FCS    |
* |  6 Bytes  |  6 Bytes  |   2 Bytes   |  Variable length   | 4 Bytes  |
* +-----------+-----------+-------------+--------------------+----------+
* FCS 不需要处理
*/
typedef struct ethernet_header {
    u_char link_dst[6];
    u_char link_src[6];
    u_short type;
} ETHERNET_HEADER;
