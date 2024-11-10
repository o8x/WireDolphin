#include "db.h"
#include "conf.h"
#include <glog/logging.h>
#include <iostream>

db::db()
    : db_(nullptr)
{
}

db& db::instance()
{
    static db ins;
    return ins;
}

void db::init(const std::string& path)
{
    if (const int rc = sqlite3_open(path.c_str(), &db_); rc) {
        throw std::runtime_error("Failed to open database: " + std::string(sqlite3_errmsg(db_)));
    }

    EXEC_SQL(R"(
-- 流表
create table if not exists streams
(
    id                   integer PRIMARY KEY AUTOINCREMENT,
    ip_version           integer default 4 not null,
    protocol             integer default 0 not null,
    hash                 text              not null,
    src_ip               text              not null,
    src_port             integer default 0 not null,
    dst_ip               text              not null,
    dst_port             integer default 0 not null,
    total_length         integer default 0 not null,
    total_payload_length integer default 0 not null,
    create_time          integer default 0 not null,
    update_time          integer default 0 not null,
    delete_time          integer default 0 not null
) strict;

create unique index hash_index on streams (hash);
create index src_ip_index on streams (src_ip);
create index dst_ip_index on streams (dst_ip);
create index dst_port_index on streams (dst_port);
create index src_port_index on streams (src_port);
create index total_length_index on streams (total_length);
create index total_payload_length_index on streams (total_payload_length);
create index five_tuple_index on streams (src_ip, src_port, dst_ip, dst_port);
)");
}

void db::close() const
{
    sqlite3_close(db_);
}

void db::execute(const std::string& sql)
{
    execute(sql, nullptr);
}

void db::execute(const std::string& sql, const std::function<void(char* msg)>& onError)
{
    const db ins = instance();
    char* errMsg = nullptr;

    if (const int rc = sqlite3_exec(ins.db_, sql.c_str(), nullptr, nullptr, &errMsg); rc != SQLITE_OK) {
        if (onError != nullptr) {
            onError(errMsg);
        }

        sqlite3_free(errMsg);
    }
}

void db::query(const std::string& sql, const std::function<void(sqlite3_stmt* stmt, const char* msg)>& onQuery)
{
    const db ins = instance();

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(ins.db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        if (onQuery != nullptr) {
            onQuery(nullptr, sqlite3_errmsg(ins.db_));
            return;
        }
    }

    onQuery(stmt, nullptr);
    sqlite3_finalize(stmt);
}
