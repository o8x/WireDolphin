#pragma once

#include <QTreeWidgetItem>
#include <QMainWindow>
#include <QLabel>
#include <QCloseEvent>
#include <QStandardItemModel>
#include <QSystemTrayIcon>

#include "packetsource.h"
#include "statswindow.h"

#define SNAP_LEN 128*1024*1024
#define PROMISC 1

QT_BEGIN_NAMESPACE

namespace Ui {
    class MainWindow;
}

QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

protected:
    void closeEvent(QCloseEvent* event) override;

public:
    void initWindow();
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;
    void changeInterfaceIndex(int index) const;
    void freePackets();
    void captureInterfaceStarted(string name, string message);
    void captureInterfaceStopped(string name, string message) const;
    void resetCapture();
    void acceptPacket(int index) const;
    void initSlots();
    void loadOfflineFile() const;
    void tableItemClicked(const QModelIndex& index);
    void toggleStartBtn();
    void initWidgets();
    void updateCaptureStatusLabel() const;
    void initInterfaceList();

private:
    Ui::MainWindow* ui;
    pcap_if_t* allDevs = nullptr;
    PacketSource* packetHandler;
    vector<Packet*> packets;
    bool captureStart = false;
    QLabel* interfaceStatusLabel = new QLabel("", this);
    QLabel* captureStatusLabel = new QLabel("", this);
    chrono::time_point<chrono::steady_clock> time_start;
    QTreeWidgetItem* frame = nullptr;
    QTreeWidgetItem* datalinkTree = nullptr;
    QTreeWidgetItem* networkTree = nullptr;
    QTreeWidgetItem* transportTree = nullptr;
    QTreeWidgetItem* applicationTree = nullptr;
    QMenu* hexTableMenu = nullptr;
    QSystemTrayIcon* systemTrayIcon = nullptr;
    StatsWindow* statsWindow = nullptr;
};
