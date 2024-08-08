#pragma once

#include <string>
#include <iostream>
#include <map>
using namespace std;

typedef struct http_header {
    bool is_request;
    string protocol;
    string method;
    string path;
    string domain;
    string user_agent;
    string host;
    map<string, string> headers;
} HTTP_HEADER;
