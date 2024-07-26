#pragma once

#include <string>
using namespace std;

class Packet {
    long len = 0;
    long caplen = 0;
    string time;

public:
    long get_len() const {
        return len;
    }

    void set_len(const long len) {
        this->len = len;
    }

    long get_caplen() const {
        return caplen;
    }

    void set_caplen(const long caplen) {
        this->caplen = caplen;
    }

    string get_time() const {
        return time;
    }

    void set_time(const string& time) {
        this->time = time;
    }
};
