#pragma once
#include <pcap/pcap.h>
#include <string>
using namespace std;

pcap_t* open_offline_pcap(const char* name, int tstamp_precision, char* error_buffer);
pcap_t* open_interface(const char* device, char* ebuf);
string get_dlt_name(pcap_t*);
string get_dlt_desc(pcap_t*);

void print_stat_info(pcap_t*, const size_t, chrono::time_point<chrono::steady_clock>);
