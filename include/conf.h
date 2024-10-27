#pragma once
#include <__format/format_functions.h>
#include <__functional/function.h>
#include <tinyxml2.h>

class conf {
    tinyxml2::XMLDocument* core_ = nullptr; // 符合 google 命名规范

    conf();
    conf(conf&) = delete;
    conf& operator=(const conf&) = delete;

public:
    void update_core() const;
    void auto_update(const std::function<void(tinyxml2::XMLDocument*)>& fn) const;
    static conf& instance();
    bool check_core_config() const;
    static std::string local_data_location();
    static std::string core_config_name();
    static void create_local_data_directory();
    std::vector<std::string> get_recent_files() const;
    void clear_recent() const;
    void append_recent_file(const std::string& name) const;
    static void create_core_config();
    [[nodiscard]] tinyxml2::XMLDocument* core() const;
    static tinyxml2::XMLElement* preferences(const std::string& name);
};
