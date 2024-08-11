#include <iostream>
#include <QMessageBox>
#include <QMenu>
#include <QFileDialog>
#include <QScrollBar>

#include "mainwindow.h"
#include <QSystemTrayIcon>
#include "interface.h"
#include "packetsource.h"
#include "ui_MainWindow.h"
#include "utils.h"

using namespace std;

#ifdef __WINDOWS__
#define HEX_TABLE_FONT_FAMILY "Consolas"
#else
#define HEX_TABLE_FONT_FAMILY "Monaco"
#endif

#define HEX_TABLE_FONT_SIZE 11
#define HEX_TABLE_SIDE_LENGTH 18

void MainWindow::closeEvent(QCloseEvent* event) {
    event->ignore();

    hide();
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    packets = vector<Packet*>();
    packetHandler = new PacketSource(this, &packets);
    systemTrayIcon = new QSystemTrayIcon();
    statsWindow = new StatsWindow();

    initWindow();
    initWidgets();
    initInterfaceList();
    initSlots();
}

void MainWindow::initWindow() {
    QIcon icon;
    icon.addPixmap(QWidget().style()->standardIcon(QStyle::SP_DriveNetIcon).pixmap(QSize(16, 16)));

    systemTrayIcon->setIcon(icon);
    systemTrayIcon->setToolTip("WireDolphin");
    systemTrayIcon->show();

    // 系统通知
    systemTrayIcon->showMessage("title", "message", QSystemTrayIcon::MessageIcon::Information, 3000);

    QMenu menu;
    QAction* stats = new QAction("Stats");
    QAction* quit = new QAction("Exit");
    menu.addActions({stats, quit});
    systemTrayIcon->setContextMenu(&menu);

    connect(stats, &QAction::triggered, this, [this]() {
        statsWindow->show();
    });

    connect(quit, &QAction::triggered, this, [this]() {
        exit(0);
    });

    connect(systemTrayIcon, &QSystemTrayIcon::activated, this, [this]() {
        show();
    });
}

MainWindow::~MainWindow() {
    packetHandler->free();
    pcap_freealldevs(allDevs);
    freePackets();

    delete ui;
    delete interfaceStatusLabel;
    delete packetHandler;
    delete captureStatusLabel;
    delete frame;
    delete datalinkTree;
    delete networkTree;
    delete transportTree;
    delete applicationTree;
    delete hexTableMenu;
    delete systemTrayIcon;
}

void MainWindow::changeInterfaceIndex(int index) const {
    ui->startBtn->setDisabled(index == 0);
    ui->loadFileBtn->setDisabled(index != 0);
}

void MainWindow::freePackets() {
    // 使用智能指针可以避免手动 delete 过程
    // 但是现在不知道智能指针的原理，暂时先手动释放
    // auto packets = vector<std::shared_ptr<Packet>>();
    // auto x = std::make_shared<Packet>();
    for_each(packets.begin(), packets.end(), [](Packet* p) {
        delete p;
    });

    // 回收内存
    packets.clear();
    vector<Packet*>().swap(packets);
}

void MainWindow::captureInterfaceStarted(string name, string message) {
    freePackets();

    time_start = std::chrono::high_resolution_clock::now();
    ui->interfaceList->setDisabled(true);
    ui->startBtn->setDisabled(false);
    ui->resetBtn->setDisabled(false);
    ui->startBtn->setText("Stop");
    ui->packetsTable->clearContents();
    ui->packetsTable->setRowCount(0);
    ui->hexTable->clearContents();
    ui->hexTable->setRowCount(0);

    ui->layerTree->clear();
    interfaceStatusLabel->setText(name.append(": ").append(message).c_str());
    updateCaptureStatusLabel();
}

void MainWindow::captureInterfaceStopped(string name, string message) const {
    ui->interfaceList->setDisabled(false);
    ui->resetBtn->setDisabled(true);
    ui->startBtn->setText("Start");
    interfaceStatusLabel->setText(name.append(": ").append(message).c_str());

    updateCaptureStatusLabel();
}

void MainWindow::resetCapture() {
    toggleStartBtn();
    toggleStartBtn();
}

void MainWindow::toggleStartBtn() {
    captureStart = !captureStart;

    QString name = ui->interfaceList->currentText();
    if (captureStart) {
        pcap_if_t* device = allDevs;
        // 从 1 开始，因为 0 是提示字符串
        for (int i = 1; i < ui->interfaceList->currentIndex(); i++) {
            device = device->next;
        }

        pcap_t* interface = open_interface(device->name, nullptr);
        if (interface == nullptr) {
            QMessageBox::warning(this, "Error", pcap_geterr(interface));
            return;
        }

        packetHandler->init(device, interface);
        packetHandler->start();

        return;
    }

    print_stat_info(packetHandler->get_interface(), packets.size(), time_start);

    packetHandler->free();
    packetHandler->wait();
}

void MainWindow::initWidgets() {
    // 设置默认拉伸因子，表格占 2/3，树占 1/3
    ui->detailSplitter->setStretchFactor(0, 2);
    ui->detailSplitter->setStretchFactor(1, 1);
    // 设置默认拉伸因子，树占 2/3，16进制查看器占 1/3
    ui->hexSplitter->setStretchFactor(0, 2);
    ui->hexSplitter->setStretchFactor(1, 1);

    captureStatusLabel->setText("waiting...");

    ui->statusBar->addWidget(interfaceStatusLabel);
    ui->statusBar->addWidget(captureStatusLabel);
    ui->startBtn->setDisabled(true);
    ui->resetBtn->setDisabled(true);
    ui->bpfEditor->setPlaceholderText(" filter expression");

    const QStringList title = {
        "NO.", "Time", "Source", "Destination", "Protocol", "Len", "Info",
    };
    ui->packetsTable->setColumnCount(title.length());
    ui->packetsTable->setFont(QFont("", 11, QFont::Normal));
    ui->packetsTable->setRowCount(0);
    ui->packetsTable->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    ui->packetsTable->setColumnWidth(0, 50);
    ui->packetsTable->setColumnWidth(1, 120);
    ui->packetsTable->setColumnWidth(2, 140);
    ui->packetsTable->setColumnWidth(3, 140);
    ui->packetsTable->setColumnWidth(4, 60);
    ui->packetsTable->setColumnWidth(5, 60);
    ui->packetsTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    ui->packetsTable->setHorizontalHeaderLabels(title);
    ui->packetsTable->setShowGrid(false);
    // 系统自带的行号
    ui->packetsTable->verticalHeader()->setVisible(false);
    ui->packetsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // 树视图
    ui->layerTree->expandAll();
    ui->layerTree->setHeaderLabel("layers");

    // hex 查看器
    const int colCount = 17;
    ui->hexTable->setRowCount(0);
    ui->hexTable->setColumnCount(colCount);
    ui->hexTable->setFont(QFont(HEX_TABLE_FONT_FAMILY, HEX_TABLE_FONT_SIZE, QFont::Normal));
    ui->hexTable->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->hexTable->horizontalHeader()->setHidden(true);
    ui->hexTable->horizontalHeader()->setVisible(false);
    ui->hexTable->setShowGrid(false);
    ui->hexTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->hexTable->setStyleSheet("QTableWidget::item{padding:0px; border:0px;}");
    ui->hexTable->setTextElideMode(Qt::ElideNone);
    for (int i = 0; i < colCount; i++) {
        ui->hexTable->setColumnWidth(i, HEX_TABLE_SIDE_LENGTH);
    }

    // 开启自定义右键菜单
    ui->hexTable->setContextMenuPolicy(Qt::CustomContextMenu);

    // TODO 回调函数
    hexTableMenu = new QMenu(ui->hexTable);
    hexTableMenu->addAction(new QAction("as HEX"));
    hexTableMenu->addAction("as ASCII");
}

void MainWindow::updateCaptureStatusLabel() const {
    if (packets.empty()) {
        captureStatusLabel->setText("");
        return;
    }

    size_t size = packets.size();
    captureStatusLabel->setText("packets: " + QString::number(size) + "/" + QString::number(packets.size()));
}

void MainWindow::acceptPacket(const int index) const {
    auto packet = packets[index];

    string src = packet->get_host_src();
    string dst = packet->get_host_dst();
    if (packet->get_port_src() != 0) {
        src = src.append(":").append(to_string(packet->get_port_src()));
        dst = dst.append(":").append(to_string(packet->get_port_dst()));
    }

    ui->packetsTable->insertRow(index);
    ui->packetsTable->setRowHeight(index, 18);

    auto* item0 = new QTableWidgetItem(QString::number(index));
    auto* item1 = new QTableWidgetItem(packet->get_time().substr(11).c_str());
    auto* item2 = new QTableWidgetItem(src.c_str());
    auto* item3 = new QTableWidgetItem(dst.c_str());
    auto* item4 = new QTableWidgetItem(packet->get_type().c_str());
    auto* item5 = new QTableWidgetItem(QString::number(packet->get_len()));
    auto* item6 = new QTableWidgetItem(packet->get_info().c_str());

    auto rgb = packet->get_color();
    auto color = QColor(rgb[0], rgb[1], rgb[2]);
    item0->setBackground(QBrush(color));
    item1->setBackground(QBrush(color));
    item2->setBackground(QBrush(color));
    item3->setBackground(QBrush(color));
    item4->setBackground(QBrush(color));
    item5->setBackground(QBrush(color));
    item6->setBackground(QBrush(color));

    ui->packetsTable->setItem(index, 0, item0);
    ui->packetsTable->setItem(index, 1, item1);
    ui->packetsTable->setItem(index, 2, item2);
    ui->packetsTable->setItem(index, 3, item3);
    ui->packetsTable->setItem(index, 4, item4);
    ui->packetsTable->setItem(index, 5, item5);
    ui->packetsTable->setItem(index, 6, item6);

    // 滚动到最底部，目前会导致表格卡顿和程序崩溃
    // ui->packetsTable->verticalScrollBar()->setValue(ui->packetsTable->verticalScrollBar()->maximum());

    updateCaptureStatusLabel();
}

void MainWindow::initSlots() {
    connect(ui->resetBtn, &QPushButton::clicked, this, &MainWindow::resetCapture);
    connect(ui->startBtn, &QPushButton::clicked, this, &MainWindow::toggleStartBtn);
    connect(ui->interfaceList, &QComboBox::currentIndexChanged, this, &MainWindow::changeInterfaceIndex);
    connect(packetHandler, &PacketSource::listen_started, this, &MainWindow::captureInterfaceStarted);
    connect(packetHandler, &PacketSource::listen_stopped, this, &MainWindow::captureInterfaceStopped);
    connect(packetHandler, &PacketSource::packet_pushed, this, &MainWindow::acceptPacket);
    connect(ui->packetsTable, &QTableWidget::clicked, this, &MainWindow::tableItemClicked);
    connect(ui->hexTable, &QTableWidget::customContextMenuRequested, this, &MainWindow::slotContextMenu);
    connect(ui->loadFileBtn, &QPushButton::clicked, this, &MainWindow::loadOfflineFile);
}

void MainWindow::loadOfflineFile() const {
    QString filename = QFileDialog::getOpenFileName(
        ui->loadFileBtn, "Select a pcap file",
        QDir::homePath(), "pcap file(*.pcap *.pcapng)"
    );

    if (filename.isEmpty()) {
        return;
    }

    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t* interface = open_offline_pcap(filename.toStdString().c_str(), 0, ebuf);
    if (interface == nullptr) {
        QMessageBox::warning(ui->loadFileBtn, "Warning", ebuf);
        return;
    }

    packetHandler->set_filename(filename.toStdString());
    packetHandler->init(nullptr, interface);
    packetHandler->start();
}

void MainWindow::slotContextMenu(QPoint pos) {
    auto index = ui->hexTable->indexAt(pos);
    if (index.isValid()) {
        hexTableMenu->exec(QCursor::pos());
    }
}

void MainWindow::tableItemClicked(const QModelIndex& index) {
    auto packet = packets[index.row()];

    delete frame;
    delete datalinkTree;
    delete networkTree;
    delete transportTree;
    delete applicationTree;

    frame = new QTreeWidgetItem(ui->layerTree);
    frame->setText(0, "frame");
    frame->setExpanded(true);
    frame->addChildren({
        new QTreeWidgetItem(QStringList(string("timestamp: ").append(packet->get_time()).c_str())),
        new QTreeWidgetItem(QStringList(string("length: ").append(to_string(packet->get_len())).c_str())),
        new QTreeWidgetItem(QStringList(string("ethernet length: ").append(to_string(14)).c_str())),
        new QTreeWidgetItem(QStringList(string("ipv4 length: ").append(to_string(packet->get_len() - 14)).c_str())),
    });

    datalinkTree = new QTreeWidgetItem(ui->layerTree);
    datalinkTree->setText(0, "data link");
    datalinkTree->setExpanded(true);
    datalinkTree->addChildren({
        new QTreeWidgetItem(QStringList(string("source: ").append(packet->get_link_src()).c_str())),
        new QTreeWidgetItem(QStringList(string("destination: ").append(packet->get_link_dst()).c_str())),
        new QTreeWidgetItem(QStringList(
            string("type: ").
            append(packet->get_type()).
            append("(hex:").
            append(to_string(packet->get_type_flag())).
            append(")").
            c_str()
        )),
    });

    networkTree = new QTreeWidgetItem(ui->layerTree);
    networkTree->setText(0, "network");
    networkTree->setExpanded(true);
    if (packet->get_type_flag() == 0x0806) {
        arp_header* arp = packet->get_arp();
        networkTree->addChildren({
            new QTreeWidgetItem(
                QStringList(string("protocol: arp").c_str())),
            new QTreeWidgetItem(
                QStringList(string("hardware type").append(to_string(arp->hardware_type)).c_str())),
            new QTreeWidgetItem(
                QStringList(string("protocol type").append(to_string(arp->protocol_type)).c_str())),
            new QTreeWidgetItem(
                QStringList(string("hardware length").append(to_string(arp->hardware_length)).c_str())),
            new QTreeWidgetItem(
                QStringList(string("protocol length").append(to_string(arp->protocol_length)).c_str())),
            new QTreeWidgetItem(
                QStringList(string("op").append(to_string(arp->op)).c_str())),
            new QTreeWidgetItem(
                QStringList(string("sender ethernet").append(bytes_to_mac(arp->sender_ethernet)).c_str())),
            new QTreeWidgetItem(
                QStringList(string("sender host").append(bytes_to_ip(arp->sender_host)).c_str())),
            new QTreeWidgetItem(
                QStringList(string("destination ethernet").append(bytes_to_mac(arp->destination_ethernet)).c_str())),
            new QTreeWidgetItem(
                QStringList(string("destination host").append(bytes_to_ip(arp->destination_host)).c_str())),
        });
    } else if (packet->get_type_flag() == 0x0800) {
        if (packet->get_ip_version() == 6) {
            ipv6_header* v6 = packet->get_ipv6();
            networkTree->addChildren({
                new QTreeWidgetItem(
                    QStringList(string("protocol: ip").c_str())),
                new QTreeWidgetItem(
                    QStringList(string("version: v6").c_str())),
                new QTreeWidgetItem(
                    QStringList(string("source: ").append(packet->get_host_src()).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("destination: ").append(packet->get_host_dst()).c_str())),
                new QTreeWidgetItem(QStringList(string("class: ").append("[x] analysis not supported").c_str())),
                new QTreeWidgetItem(QStringList(string("flow label: ").append("[x] analysis not supported").c_str())),
                new QTreeWidgetItem(
                    QStringList(string("next header: ").append(to_string(v6->next_header)).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("hop limit: ").append(to_string(v6->hop_limit)).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("payload length: ").append(to_string(v6->payload_length)).c_str())),
                new QTreeWidgetItem(QStringList(string("options: ").append("[x] analysis not supported").c_str())),
            });
        } else {
            ipv4_header* v4 = packet->get_ipv4();
            networkTree->addChildren({
                new QTreeWidgetItem(
                    QStringList(string("protocol: ip").c_str())),
                new QTreeWidgetItem(
                    QStringList(string("version: v").append(to_string((v4->version_ihl & 0xf0) >> 4)).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("source: ").append(packet->get_host_src()).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("destination: ").append(packet->get_host_dst()).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("header length: ").append(to_string((v4->version_ihl & 0xf) * 4)).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("service type: ").append(to_string(v4->type_of_service)).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("identifier: ").append(to_string(v4->identification)).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("fragment_offset: ").append(to_string(v4->flags_fragment)).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("time to live: ").append(to_string(v4->time_to_live)).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("protocol: ").append(to_string(v4->protocol)).c_str())),
                new QTreeWidgetItem(
                    QStringList(string("checksum: ").append(to_string(v4->header_checksum)).c_str())),
                new QTreeWidgetItem(QStringList(string("options: ").append("[x] analysis not supported").c_str())),
            });
        }
    }

    transportTree = new QTreeWidgetItem(ui->layerTree);
    transportTree->setText(0, "transport");
    transportTree->setExpanded(true);

    if (auto tcp = packet->get_tcp(); tcp != nullptr) {
        transportTree->addChildren({
            new QTreeWidgetItem(QStringList(string("protocol: tcp").c_str())),
            new QTreeWidgetItem(QStringList(string("source port: ").append(to_string(tcp->src_port)).c_str())),
            new QTreeWidgetItem(QStringList(string("destination port: ").append(to_string(tcp->dst_port)).c_str())),
            new QTreeWidgetItem(QStringList(string("seq number: ").append(to_string(tcp->seq_number)).c_str())),
            new QTreeWidgetItem(QStringList(string("ack: ").append(to_string(tcp->ack_number)).c_str())),
            new QTreeWidgetItem(
                QStringList(string("data offset: ").append(to_string(packet->get_tcp_header_len())).c_str())),
            new QTreeWidgetItem(QStringList(string("window: ").append(to_string(tcp->window)).c_str())),
            new QTreeWidgetItem(QStringList(string("checksum: ").append(to_string(tcp->checksum)).c_str())),
            new QTreeWidgetItem(QStringList(string("urgent: ").append(to_string(tcp->urgent)).c_str())),
            new QTreeWidgetItem(QStringList(string("flags:").c_str())),
            new QTreeWidgetItem(
                QStringList(string(" - CWR: ").append(to_string(packet->get_tcp_flags()->CWR)).c_str())),
            new QTreeWidgetItem(
                QStringList(string(" - ECE: ").append(to_string(packet->get_tcp_flags()->ECE)).c_str())),
            new QTreeWidgetItem(
                QStringList(string(" - URG: ").append(to_string(packet->get_tcp_flags()->URG)).c_str())),
            new QTreeWidgetItem(
                QStringList(string(" - ACK: ").append(to_string(packet->get_tcp_flags()->ACK)).c_str())),
            new QTreeWidgetItem(
                QStringList(string(" - PSH: ").append(to_string(packet->get_tcp_flags()->PSH)).c_str())),
            new QTreeWidgetItem(
                QStringList(string(" - RST: ").append(to_string(packet->get_tcp_flags()->RST)).c_str())),
            new QTreeWidgetItem(
                QStringList(string(" - SYN: ").append(to_string(packet->get_tcp_flags()->SYN)).c_str())),
            new QTreeWidgetItem(
                QStringList(string(" - FIN: ").append(to_string(packet->get_tcp_flags()->FIN)).c_str())),
        });
    } else if (auto udp = packet->get_udp(); udp != nullptr) {
        transportTree->addChildren({
            new QTreeWidgetItem(QStringList(string("protocol: udp").c_str())),
            new QTreeWidgetItem(QStringList(string("source port: ").append(to_string(udp->src_port)).c_str())),
            new QTreeWidgetItem(QStringList(string("destination port: ").append(to_string(udp->dst_port)).c_str())),
            new QTreeWidgetItem(QStringList(string("total length: ").append(to_string(udp->total_length)).c_str())),
            new QTreeWidgetItem(QStringList(string("checksum: ").append(to_string(udp->checksum)).c_str())),
        });
    }

    applicationTree = new QTreeWidgetItem(ui->layerTree);
    applicationTree->setText(0, "application");
    applicationTree->setExpanded(true);
    applicationTree->addChildren({
        new QTreeWidgetItem(QStringList(string("[x] analysis not supported").c_str())),
    });

    // hex 查看器
    ui->hexTable->clearContents();
    ui->hexTable->setRowCount(0);

    const int line_count = ceil(static_cast<float>(packet->get_len()) / static_cast<float>(16));
    for (int i = 0; i < line_count; i++) {
        ui->hexTable->insertRow(i);
        ui->hexTable->setRowHeight(i, HEX_TABLE_SIDE_LENGTH);
    }

    int row = 0;
    const u_char* payload = packet->get_payload();
    for (int i = 0; i < packet->get_len(); i++) {
        if (i > 0 && i % 16 == 0) {
            row++;
        }

        // 第8个保留空白
        if (i % 8 == 0 && i % 16 != 0) {
            ui->hexTable->setItem(row, 8, new QTableWidgetItem(""));
        }

        // 当求余16大于8时说明数字介于 8 - 16之间
        // 需要向右移动一个格子，避免占用刚才的空格
        int index = i % 16 < 8 ? i % 16 : (i % 16) + 1;
        ui->hexTable->setItem(row, index, new QTableWidgetItem(byte_to_ascii(payload[i]).c_str()));
    }
}

void MainWindow::initInterfaceList() {
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&allDevs, error_buffer) != 0) {
        ui->interfaceList->addItem(QString::fromStdString(error_buffer));
        return;
    }

    ui->interfaceList->addItem(QString::fromStdString("Choose interface"));
    if (allDevs == nullptr) {
        return;
    }

    pcap_if_t* dev = allDevs;
    while (true) {
        if (dev->flags > PCAP_IF_RUNNING) {
            ui->interfaceList->addItem(QString::fromStdString(dev->name));
        }

        if (dev->next == nullptr) {
            break;
        }

        dev = dev->next;
    }
}
