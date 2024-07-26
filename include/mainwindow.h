#pragma once

#include <QMainWindow>
#include <QLabel>
#include <QStandardItemModel>

#include "packetsource.h"

#define SNAP_LEN 128*1024*1024
#define PROMISC 1

QT_BEGIN_NAMESPACE

namespace Ui {
    class MainWindow;
}

QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;
    void changeInterfaceIndex(int index);
    void captureInterfaceStarted(std::string name, std::string message);
    void captureInterfaceStopped(std::string name, std::string message);
    void resetCapture();
    void acceptPacket(const Packet&);
    void initSlots();
    void toggleStartBtn();
    void initWidgets();
    void updateCaptureStatusLabel() const;
    void initInterfaceList();

private:
    Ui::MainWindow* ui;
    pcap_if_t* allDevs;
    PacketSource* packetHandler;
    bool captureStart = false;
    char error_buffer[PCAP_ERRBUF_SIZE];
    QLabel* interfaceStatusLabel = new QLabel("", this);
    QLabel* captureStatusLabel = new QLabel("", this);
    int count;
};
