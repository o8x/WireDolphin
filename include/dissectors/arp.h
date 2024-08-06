#pragma once

#include <string>
#include <iostream>
using namespace std;

/*
 * +0---------------1-----------------2--------------3----------------4|
 * |                                  |           Hardware Type        |
 * +----------------------------------|----------------|---------------|
 * |           Protocol Type          | Hardware Length|Protocol Length|
 * +----------------------------------|--------------------------------|
 * |              OP                  |                                |
 * +----------------------------------+                                |
 * |                Ethernet Address of Sender(0-47)                   |
 * +-------------------------------------------------------------------|
 * |                         IP Address of Sender                      |
 * +-------------------------------------------------------------------|
 * |                Ethernet Address of Destination(0-47)              |
 * +                                  +--------------------------------|
 * |                                  | IP Address of Destination(0-15)|
 * +----------------------------------|--------------------------------|
 * | IP Address of Destination(16-31) |
 * +----------------------------------|
 */
typedef struct arp_header {
    u_short hardware_type;
    u_short protocol_type;
    u_char hardware_length;
    u_char protocol_length;
    u_short op;
    u_char sender_ethernet[6];
    u_char sender_host[4];
    u_char destination_ethernet[6];
    u_char destination_host[4];
} ARP_HEADER;
