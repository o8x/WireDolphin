#include <QApplication>
#include <QMenu>
#include <QSystemTrayIcon>
#include <glog/logging.h>
#include <iostream>
#include <mainwindow.h>

void initGlog(const char* argv0)
{
    google::InitGoogleLogging(argv0);
    FLAGS_minloglevel = google::INFO;
    FLAGS_timestamp_in_logfile_name = false;
    FLAGS_max_log_size = 128;
    FLAGS_logbufsecs = 15;
    FLAGS_logbuflevel = google::INFO;
    FLAGS_log_utc_time = true;
    FLAGS_log_dir = "../logs";

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
    initGlog(argv[0]);
    QApplication a(argc, argv);

    try {

        MainWindow w;
        // QT 似乎无法实现 titlebar hidden inset 的效果，只能完全隐藏边框
        // w.setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
        // w.move(50, 50);
        // 标题默认有 28 的高度
        w.resize(1700, 1000 - 28);
        // 在 Mac 下合并标题和工具栏
        w.setUnifiedTitleAndToolBarOnMac(true);
        w.setWindowTitle("🐬 WireDolphin");
        w.show();

        return QApplication::exec();
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 1;
}
