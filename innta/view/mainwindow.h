#pragma once

#include "packetsource.h"
#include "preferenceswindow.h"
#include "statswindow.h"
#include "trayicon.h"
#include <QCloseEvent>

#define SNAP_LEN 128 * 1024 * 1024
#define PROMISC 1
#define MENUBAT_ITEM_MIN_WIDTH 200

QT_BEGIN_NAMESPACE

namespace Ui {
class MainWindow;
}

QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

protected:
    void closeEvent(QCloseEvent* event) override;
    bool event(QEvent* event) override;

public:
    void initWindow();
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;
    void changeInterfaceIndex(int index) const;
    void captureInterfaceStarted(packetsource_state state);
    void captureInterfaceStopped(packetsource_state state) const;
    void resetCapture();
    void acceptPacket(int index, Packet* p) const;
    void initSlots();
    void loadOfflinePcap(string filename) const;
    void openLoadOfflineFileDialog() const;
    void tableItemClicked(const QModelIndex& index);
    void toggleStartBtn();
    void initWidgets();
    void initInterfaceList();
    void about();
    void activateStatsWindow() const;
    void saveAsPcap();
    void initMenus();
    void updateMajorView(size_t, size_t) const;

private:
    Ui::MainWindow* ui;
    pcap_if_t* allDevs = nullptr;
    PacketSource* packetSource;
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
    TrayIcon* trayIcon = nullptr;
    StatsWindow* statsWindow = nullptr;
    PreferencesWindow* preferencesWindow;
    QMenu* fileMenu = nullptr;
    QMenu* helpMenu = nullptr;
    QMenu* windowMenu = nullptr;
    QMenu* lastFiles = nullptr;
    QAction* clearLastFiles = nullptr;
    QAction* loadFileAct = nullptr;
    QAction* saveAct = nullptr;
    QAction* dumpFilename = nullptr;
    QAction* aboutAct = nullptr;
    QAction* statsAct = nullptr;
    QAction* aboutQtAct = nullptr;
    QAction* clearRecentAction = nullptr;
    QAction* preferencesAction = nullptr;
};
