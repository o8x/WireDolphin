#include <iostream>
#include <mainwindow.h>
#include <QApplication>
#include <QPushButton>

int main(int argc, char* argv[]) {
    QApplication a(argc, argv);

    try {
        MainWindow w;
        w.setWindowTitle("🐬 WireDolphin");
        w.show();

        return QApplication::exec();
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 1;
}
