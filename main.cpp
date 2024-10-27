#include "conf.h"
#include "locale.hpp"

#include <QApplication>
#include <fstream>
#include <glog/logging.h>
#include <iostream>
#include <mainwindow.h>
#include <unistd.h>

void initGlog(const char* argv0)
{
    auto baseDir = conf::instance().core()->FirstChildElement("Logger")->FirstChildElement("BaseDir");

    google::InitGoogleLogging(argv0);
    FLAGS_minloglevel = google::INFO;
    FLAGS_timestamp_in_logfile_name = false;
    FLAGS_max_log_size = 128;
    FLAGS_logbufsecs = 15;
    FLAGS_logbuflevel = google::INFO;
    FLAGS_log_utc_time = true;
    if (baseDir == nullptr) {
        FLAGS_log_dir = baseDir->Value();
    } else {
        FLAGS_log_dir = "../logs";
    }

#ifdef DEBUG_BUILD
    FLAGS_logtostderr = true;
    FLAGS_logtostdout = true;
    FLAGS_colorlogtostderr = true;
    FLAGS_colorlogtostdout = true;

    LOG(INFO) << "golog work on debug, contents will be output to stdout.";
#endif
}

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);

    try {
        if (!conf::instance().check_core_config()) {
            throw runtime_error(std::format("Core Profile is corrupt, Repair or remove \"{}\".", conf::core_config_name()));
        }

        // 设置语言
        lc::Locale::setLocale(static_cast<lc::Locales>(conf::preferences("Language")->IntText()));

        initGlog(argv[0]);

        MainWindow window;
        auto winConf = conf::instance().core()->FirstChildElement("Window");

        // QT 似乎无法实现 titlebar hidden inset 的效果，只能完全隐藏边框
        // w.setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
        window.resize(winConf->FirstChildElement("Width")->IntText(), winConf->FirstChildElement("Height")->IntText());
        window.move(winConf->FirstChildElement("PosX")->IntText(), winConf->FirstChildElement("PosY")->IntText());
        // 在 Mac 下合并标题和工具栏
        window.setUnifiedTitleAndToolBarOnMac(true);
        window.setWindowTitle(TL_APP_TITLE.c_str());
        window.setWindowIcon(QIcon(":/icons/icon_128x128@2x.png"));
        window.show();

        return QApplication::exec();
    } catch (const std::runtime_error& e) {
        QMessageBox::warning(nullptr, "FATAL ERROR",e.what());
    }

    return 1;
}
