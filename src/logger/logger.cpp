#include "logger.h"

#include <cstdarg>
#include <iostream>
#include <ostream>

namespace logger {
void error(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, "[ERR]: ", nullptr);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void info(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, "[INF]: ", nullptr);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

void infoln(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, "[INF]: ", nullptr);
    vfprintf(stdout, fmt, ap);
    vfprintf(stdout, "\n", nullptr);
    va_end(ap);
}

void errorln(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, "[ERR]: ", nullptr);
    vfprintf(stderr, fmt, ap);
    vfprintf(stderr, "\n", nullptr);
    va_end(ap);
}
}
