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
