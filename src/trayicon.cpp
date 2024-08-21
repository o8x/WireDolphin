#include "trayicon.h"

TrayIcon::TrayIcon(QSystemTrayIcon* t, QWidget* wdi)
    : wdi(wdi)
    , tray(t)
{
    wdi->setWindowModality(Qt::NonModal);
    wdi->setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
    tray->show();

    connect(tray, &QSystemTrayIcon::activated, this, &TrayIcon::onActivated);
}

TrayIcon::~TrayIcon()
{
    delete tray;
    delete wdi;
}

void TrayIcon::onActivated(QSystemTrayIcon::ActivationReason reason) const
{
    // 图标的位置的 x 是屏幕最左侧到图标最左侧的距离
    // 如果要让窗体与图标垂直中心对齐，则需要在窗口移动时加上图标一半的宽度
    double icon_center_offset = static_cast<double>(tray->geometry().size().width()) / 2;
    double frame_center_offset = static_cast<double>(wdi->size().width()) / 2;
    double x = tray->geometry().x() + icon_center_offset - frame_center_offset;

    // 发生点击时，如果窗体不在计算得出的坐标，则移动过去。
    if (wdi->geometry().x() != x) {
        // 窗体的 Y 坐标取图标的高度 + 10
        wdi->move(x, tray->geometry().size().height() + 5);
    }

    switch (reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
        if (wdi->isHidden()) {
            wdi->show();
            wdi->raise();
            wdi->activateWindow();
        } else {
            wdi->hide();
        }

        break;
    case QSystemTrayIcon::MiddleClick:
        // 中键
            break;
    case QSystemTrayIcon::Context:
        // 右键
            break;
    default:
        break;
    }
}
