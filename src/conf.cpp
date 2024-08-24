#include "conf.h"
#include "utils.h"
#include <QMessageBox>
#include <__filesystem/operations.h>
#include <qstandardpaths.h>
#define CORE_CONFIG_FILENAME "Core.xml"

conf::conf()
{
    // 文件不存在时创建默认配置文件
    if (file_not_exist(core_config_name())) {
        create_core_config();
    }

    // 加载核心配置文件
    this->core_ = new tinyxml2::XMLDocument();
    int code = this->core_->LoadFile(core_config_name().c_str());
    if (code != tinyxml2::XML_SUCCESS) {
        throw std::runtime_error(std::format("Load Core Profile Failed, code: {}", code));
    }
}

void conf::update_core() const
{
    core_->SaveFile(core_config_name().c_str());
}

void conf::auto_update(const std::function<void(tinyxml2::XMLDocument*)>& fn) const
{
    fn(core_);
    update_core();
}

// 单例模式加载配置文件
// 该函数一定要在 QApplication 初始化完成之后调用
// 否则 AppName 无法初始化，获取到的将是无效的路径
conf& conf::instance()
{
    static conf ins;
    return ins;
}

bool conf::check_core_config() const
{
    return core_->FirstChildElement("Logger") != nullptr && core_->FirstChildElement("Window") != nullptr;
}

std::string conf::local_data_location()
{
    return QStandardPaths::standardLocations(QStandardPaths::AppDataLocation)[0]
        .toStdString();
}

std::string conf::core_config_name()
{
    return std::format("{}/{}", local_data_location(), CORE_CONFIG_FILENAME);
}

void conf::create_local_data_directory()
{
    std::error_code code;
    if (std::filesystem::create_directory(local_data_location(), code)) {
        return;
    }

    if (code.value() != 0) {
        throw std::runtime_error(code.message());
    }
}

std::vector<std::string> conf::get_recent_files() const
{
    std::vector<std::string> res;

    auto* list = core_->FirstChildElement("RecentFileList");
    if (list == nullptr) {
        return res;
    }

    // 查询是否已经存在过
    auto* head = list->FirstChildElement("Item");

    do {
        res.emplace_back(head->GetText());
        head = head->NextSiblingElement("Item");
    } while (head != nullptr);

    return res;
}

void conf::clear_recent() const
{
    auto* list = core_->FirstChildElement("RecentFileList");
    core_->DeleteNode(list);
    update_core();
}

void conf::append_recent_file(const std::string& name) const
{
    auto* list = core_->FirstChildElement("RecentFileList");
    if (list == nullptr) {
        core_->InsertFirstChild(core_->NewElement("RecentFileList"));
        list = core_->FirstChildElement("RecentFileList");
    }

    // 查询是否已经存在过
    auto* head = list->FirstChildElement("Item");

    do {
        if (const char* text = head->GetText(); name.c_str() == text) {
            return;
        }

        head = head->NextSiblingElement("Item");
    } while (head != nullptr);

    auto item = core_->NewElement("Item");
    item->SetText(name.c_str());
    list->InsertFirstChild(item);
}

void conf::create_core_config()
{
    // 创建配置文件夹
    create_local_data_directory();

    // 生成默认配置文件
    tinyxml2::XMLDocument doc;
    tinyxml2::XMLDeclaration* declaration = doc.NewDeclaration();
    doc.InsertFirstChild(declaration);

    auto logger = doc.NewElement("Logger");

#ifdef __linux__
    std::string logDir = "/var/log";
#elif __APPLE__
    std::string home = QStandardPaths::standardLocations(QStandardPaths::HomeLocation)[0].toStdString();
    std::string logDir = std::format("{}/Library/Logs/", home);
#else
    std::string logDir = "../logs";
#endif

    logger->InsertNewChildElement("BaseDir")->SetText(logDir.c_str());

    auto* window = doc.NewElement("Window");
    window->InsertNewChildElement("Width")->SetText(1700);
    // 标题默认有 28 的高度
    window->InsertNewChildElement("Height")->SetText(1000 - 28);
    window->InsertNewChildElement("PosX")->SetText(50);
    window->InsertNewChildElement("PosY")->SetText(50);

    doc.InsertEndChild(doc.NewElement("RecentFileList"));
    doc.InsertEndChild(logger);
    doc.InsertEndChild(window);
    doc.SaveFile(core_config_name().c_str());
}

tinyxml2::XMLDocument* conf::core() const
{
    return core_;
}
