#include "conf.h"

#include <__filesystem/operations.h>
#include <qstandardpaths.h>
#include <unistd.h>

#include <QMessageBox>
#define CORE_CONFIG_FILENAME "Core.xml"

conf::conf()
{
    // 文件不存在时创建默认配置文件
    if (access(core_config_name().c_str(), F_OK) != 0) {
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

void conf::create_core_config()
{
    // 创建配置文件夹
    create_local_data_directory();

    // 生成默认配置文件
    tinyxml2::XMLDocument doc;
    tinyxml2::XMLDeclaration* declaration = doc.NewDeclaration();
    doc.InsertFirstChild(declaration);

    auto logger = doc.NewElement("Logger");
    logger->InsertNewChildElement("BaseDir")->SetText("../logs");

    auto* window = doc.NewElement("Window");
    window->InsertNewChildElement("Width")->SetText(1700);
    // 标题默认有 28 的高度
    window->InsertNewChildElement("Height")->SetText(1000 - 28);
    window->InsertNewChildElement("PosX")->SetText(50);
    window->InsertNewChildElement("PosY")->SetText(50);

    doc.InsertEndChild(logger);
    doc.InsertEndChild(window);
    doc.SaveFile(core_config_name().c_str());
}

tinyxml2::XMLDocument* conf::core() const
{
    return core_;
}
