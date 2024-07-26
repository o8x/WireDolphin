#pragma once
#include <string>
#include <pcap/pcap.h>
using namespace std;

pcap_t* open_interface(const char* device, char* ebuf);
string get_dlt_name(pcap_t*);
string get_dlt_desc(pcap_t*);

void print_stat_info(pcap_t* inet, int packet_num);
