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

[[nodiscard]] string byte_to_ascii(const u_char byte) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << ntohs(byte << 8);

    if (oss.str().length() == 1) {
        return string("0").append(oss.str());
    }

    return oss.str();
}

string bytes_to_mac(const u_char addr[6]) {
    return bytes_to_ascii(addr, 6, ":");
}

string bytes_to_ip(const u_char host[4]) {
    return string(to_string(int(host[0]))).
           append(".").
           append(to_string(int(host[1]))).append(".").
           append(to_string(int(host[2]))).append(".").
           append(to_string(int(host[3])));
}

string is_restful_request(std::istringstream& stream) {
    char head[5];
    stream.read(head, 4);
    head[4] = '\0'; // 字符串比较必须以 \0 结束，需要 strcpy 或者手动添加 \0

    if (strcmp(head, "GET ") == 0) {
        return "GET";
    }

    if (strcmp(head, "POST") == 0) {
        return "POST";
    }

    if (strcmp(head, "PUT ") == 0) {
        return "PUT";
    }

    if (strcmp(head, "HEAD") == 0) {
        return "HEAD";
    }

    // 移动到数据头，重新读取
    stream.seekg(0, std::ios::beg);
    char method[7];
    stream.read(method, 6);
    method[6] = '\0';

    if (strcmp(method, "DELETE") == 0) {
        return "DELETE";
    }

    if (strcmp(method, "OPTION") == 0) {
        return "OPTION";
    }

    if (strcmp(method, "TRACE ") == 0) {
        return "TRACE";
    }

    if (strcmp(method, "PATCH ") == 0) {
        return "PATCH";
    }

    if (strcmp(method, "CONNEC") == 0) {
        return "CONNECT";
    }

    return "";
}
