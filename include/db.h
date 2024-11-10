#pragma once
#include <__functional/function.h>
#include <glog/logging.h>
#include <sqlite3.h>
#include <string>

#define EXEC_SQL(sql) db::execute(sql, [](const char* msg) { \
    if (msg == nullptr) {                                    \
        return;                                              \
    }                                                        \
    LOG(ERROR) << "SQL Error: " << msg << std::endl;         \
})

#define INSERT(sql) EXEC_SQL(sql)
#define UPDATE(sql) EXEC_SQL(sql)
#define QUERY_SQL db::query

class db {
    sqlite3* db_;

public:
    db();
    static db& instance();
    void init(const std::string& path);
    void close() const;
    static void execute(const std::string& sql);
    static void execute(const std::string&, const std::function<void(char* msg)>& onError);
    static void query(const std::string&, const std::function<void(sqlite3_stmt* stmt, const char* msg)>& onQuery);
};
