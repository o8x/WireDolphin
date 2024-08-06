#include <iostream>
#include <mainwindow.h>
#include <QApplication>
#include <QPushButton>

int main(int argc, char* argv[]) {
    QApplication a(argc, argv);

    try {
        MainWindow w;
        // QT 似乎无法实现 titlebar hidden inset 的效果，只能完全隐藏边框
        // w.setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
        // 在 Mac 下合并标题和工具栏
        w.move(50, 50);
        w.setUnifiedTitleAndToolBarOnMac(true);
        w.setWindowTitle("🐬 WireDolphin");
        w.show();

        return QApplication::exec();
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 1;
}
