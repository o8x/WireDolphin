#pragma once
#include <__format/format_functions.h>
#include <tinyxml2.h>

class conf {
    tinyxml2::XMLDocument* core_ = nullptr; // 符合 google 命名规范

    conf();
    conf(conf&) = delete;
    conf& operator=(const conf&) = delete;

public:
    void update_core() const;
    static conf& instance();
    bool check_core_config() const;
    static std::string local_data_location();
    static std::string core_config_name();
    static void create_local_data_directory();
    static void create_core_config();
    [[nodiscard]] tinyxml2::XMLDocument* core() const;
};
