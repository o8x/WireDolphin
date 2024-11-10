#pragma once

#include <iostream>
#include <string>
using namespace std;
/**
 * 检测文件是否不存在
 */
bool file_not_exist(const string& name);

string format_timeval_to_string(const timeval&);

/**
 * 字节数据转 ASCII 字符串
 */
string bytes_to_ascii(const u_char* byte, int size, const string& spliter = " ");
string bytes_to_string(const u_char* byte, int size, const string& spliter);
string byte_to_ascii(const u_char byte);
string bytes_to_mac(const u_char addr[6]);
string bytes_to_ip(const u_char host[4]);
string is_restful_request(std::istringstream& stream);
uint64_t hash_string(const std::string &);
