#include "utils.h"
#include <iomanip>
#include <iostream>
#include <sstream>
using namespace std;

string format_timeval_to_string(const timeval& tv) {
    std::time_t tt = tv.tv_sec;
    std::tm* tm_info = std::localtime(&tt);

    std::ostringstream oss;

    oss << std::put_time(tm_info, "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(6) << tv.tv_usec;

    return oss.str();
}

string bytes_to_ascii(const u_char* byte, int size, const string& spliter) {
    std::ostringstream oss;
    for (int i = 0; i < size; i++) {
        // 因为是 ASCII 字符，所以只需要十六进制的前两位即可，大端序取高八位就是前两位，再转换网络序就可以获得char的数字
        oss << std::hex << ntohs(byte[i] << 8);
        if (i != size - 1) {
            oss << spliter;
        }
    }

    return oss.str();
}

string bytes_to_string(const u_char* byte, int size, const string& spliter) {
    std::ostringstream oss;
    for (int i = 0; i < size; i++) {
        oss << std::hex << ntohs(byte[i]);
        if (i != size - 1) {
            oss << spliter;
        }
    }

    return oss.str();
}

string byte_to_ascii(const u_char byte) {
    std::ostringstream oss;
    oss << std::hex << ntohs(byte << 8);
    return oss.str();
}
