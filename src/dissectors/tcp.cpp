#include "dissectors/tcp.h"

#include <iostream>

void parse_tcp_flags(tcp_flags* dst, u_char flags)
{
    dst->CWR = (flags >> 7) & 1;
    dst->ECE = (flags >> 6) & 1;
    dst->URG = (flags >> 5) & 1;
    dst->ACK = (flags >> 4) & 1;
    dst->PSH = (flags >> 3) & 1;
    dst->RST = (flags >> 2) & 1;
    dst->SYN = (flags >> 1) & 1;
    dst->FIN = (flags >> 0) & 1;
}
