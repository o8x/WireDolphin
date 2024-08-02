#pragma once

#include <QTreeWidgetItem>
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
    void freePackets();
    void captureInterfaceStarted(string name, string message);
    void captureInterfaceStopped(string name, string message) const;
    void resetCapture();
    void acceptPacket(int index) const;
    void initSlots();
    void tableItemClicked(const QModelIndex& index);
    void toggleStartBtn();
    void initWidgets();
    void updateCaptureStatusLabel() const;
    void initInterfaceList();

private:
    Ui::MainWindow* ui;
    pcap_if_t* allDevs;
    PacketSource* packetHandler;
    vector<Packet*> packets;
    bool captureStart = false;
    char error_buffer[PCAP_ERRBUF_SIZE];
    QLabel* interfaceStatusLabel = new QLabel("", this);
    QLabel* captureStatusLabel = new QLabel("", this);
    chrono::time_point<chrono::steady_clock> time_start;
    QTreeWidgetItem* datalinkTree = nullptr;
    QTreeWidgetItem* networkTree = nullptr;
    QTreeWidgetItem* transportTree = nullptr;
    QTreeWidgetItem* applicationTree = nullptr;
};
