#pragma once

#include <QSystemTrayIcon>
#include <QWidget>

class TrayIcon : public QWidget {
    QSystemTrayIcon* tray;
    QWidget* wdi = nullptr;

public:
    explicit TrayIcon(QSystemTrayIcon* t, QWidget* wdi);
    ~TrayIcon();
    void onActivated(QSystemTrayIcon::ActivationReason reason) const;
};
