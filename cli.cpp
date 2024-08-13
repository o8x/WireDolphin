#include "interface.h"
#include "unistd.h"
#include <iostream>

pcap_t* inet = open_interface("en1", nullptr);
int packet_num = 0;

void signalHandler(int)
{
    pcap_stat stats;
    pcap_stats(inet, &stats);

    std::cout << packet_num << " captured" << std::endl;
    std::cout << stats.ps_recv << " received by filter" << std::endl;
    std::cout << stats.ps_ifdrop << " dropped by interface" << std::endl;
    std::cout << stats.ps_drop << " dropped by kernel" << std::endl;
}

void read_packet(u_char* user, const pcap_pkthdr* pkt_header, const u_char*)
{
    packet_num++;
}

int main(int, char*[])
{
    signal(SIGUSR1, signalHandler);

    std::cout << getpid() << std::endl;

    pcap_loop(inet, -1, read_packet, nullptr);
    return 0;
}
