#pragma once

namespace logger {
void info(const char* fmt, ...);
void error(const char* fmt, ...);
void infoln(const char* fmt, ...);
void errorln(const char* fmt, ...);
}
