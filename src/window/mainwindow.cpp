#include "mainwindow.h"

#include "conf.h"
#include "interface.h"
#include "packetsource.h"
#include "ui_MainWindow.h"
#include "utils.h"

#include <QFileDialog>
#include <QMenu>
#include <QMessageBox>
#include <QSystemTrayIcon>
#include <glog/logging.h>
#include <iostream>

using namespace Qt::StringLiterals;

using namespace std;

#ifdef __WINDOWS__
#define HEX_TABLE_FONT_FAMILY "Consolas"
#else
#define HEX_TABLE_FONT_FAMILY "Monaco"
#endif

#define HEX_TABLE_FONT_SIZE 11
#define HEX_TABLE_SIDE_LENGTH 18 // 最小尺寸 19 * 22

void MainWindow::closeEvent(QCloseEvent* event)
{
    event->ignore();

    hide();
}
bool MainWindow::event(QEvent* event)
{
    if (event->type() == QEvent::Move) {
        auto winConf = conf::instance().core()->FirstChildElement("Window");
        winConf->FirstChildElement("PosX")->SetText(this->geometry().x());
        winConf->FirstChildElement("PosY")->SetText(this->geometry().y());

        conf::instance().update_core();
    }

    if (event->type() == QEvent::Resize) {
        auto winConf = conf::instance().core()->FirstChildElement("Window");
        winConf->FirstChildElement("Width")->SetText(this->geometry().size().width());
        winConf->FirstChildElement("Height")->SetText(this->geometry().size().height());

        conf::instance().update_core();
    }

    return QMainWindow::event(event);
}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    packets = vector<Packet*>();
    packetSource = new PacketSource(this, &packets);
    statsWindow = new StatsWindow();
    statsWindow->packetSource = packetSource;
    statsWindow->initGraph();

    initMenus();
    initWindow();
    initWidgets();
    initInterfaceList();
    initSlots();
}

void MainWindow::initWindow()
{

    QSystemTrayIcon* tray = new QSystemTrayIcon();
    tray->setToolTip("WireDolphin");

    QIcon icon;
    icon.addPixmap(QWidget().style()->standardIcon(QStyle::SP_DriveNetIcon).pixmap(QSize(16, 16)));
    tray->setIcon(icon);

    trayIcon = new TrayIcon(tray, statsWindow);
}

MainWindow::~MainWindow()
{
    packetSource->free();
    pcap_freealldevs(allDevs);
    freePackets();

    delete ui;
    delete interfaceStatusLabel;
    delete packetSource;
    delete captureStatusLabel;
    delete frame;
    delete datalinkTree;
    delete networkTree;
    delete transportTree;
    delete applicationTree;
    delete hexTableMenu;
    delete trayIcon;
    delete statsWindow;
    delete fileMenu;
    delete helpMenu;
    delete windowMenu;
    delete statsAct;
    delete saveAct;
    delete dumpFilename;
    delete loadFileAct;
    delete aboutAct;
    delete aboutQtAct;
}

void MainWindow::changeInterfaceIndex(int index) const
{
    ui->startBtn->setDisabled(index == 0);
    ui->loadFileBtn->setDisabled(index != 0);
}

void MainWindow::freePackets()
{
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

void MainWindow::captureInterfaceStarted(packetsource_state state)
{
    freePackets();

    if (!state.dump_filename.empty()) {
        dumpFilename->setText(state.dump_filename.c_str());
    }

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
    interfaceStatusLabel->setText(state.interface_name.append(": ").append(state.state).c_str());
    updateCaptureStatusLabel();
}

void MainWindow::captureInterfaceStopped(packetsource_state state) const
{
    ui->interfaceList->setDisabled(false);
    ui->resetBtn->setDisabled(true);
    ui->startBtn->setText("Start");
    interfaceStatusLabel->setText(state.interface_name.append(": ").append(state.state).c_str());

    updateCaptureStatusLabel();
}

void MainWindow::resetCapture()
{
    toggleStartBtn();
    toggleStartBtn();
}

void MainWindow::toggleStartBtn()
{
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

        packetSource->init(device, interface);
        packetSource->start();

        return;
    }

    print_stat_info(packetSource->get_interface(), packets.size(), time_start);

    packetSource->free();
    packetSource->wait();
}

void MainWindow::initWidgets()
{
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
        "NO.",
        "Time",
        "Source",
        "Destination",
        "Protocol",
        "Len",
        "Info",
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

    // ascii 查看器
    ui->asciiViewTable->setRowCount(0);
    ui->asciiViewTable->setColumnCount(colCount);
    ui->asciiViewTable->setFont(QFont(HEX_TABLE_FONT_FAMILY, HEX_TABLE_FONT_SIZE, QFont::Normal));
    ui->asciiViewTable->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->asciiViewTable->horizontalHeader()->setHidden(true);
    ui->asciiViewTable->horizontalHeader()->setVisible(false);
    ui->asciiViewTable->setShowGrid(false);
    ui->asciiViewTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->asciiViewTable->setTextElideMode(Qt::ElideNone);
    for (int i = 0; i < colCount; i++) {
        ui->asciiViewTable->setColumnWidth(i, HEX_TABLE_SIDE_LENGTH / 2);
    }
}

void MainWindow::updateCaptureStatusLabel() const
{
    if (packets.empty()) {
        captureStatusLabel->setText("");
        return;
    }

    size_t size = packets.size();
    captureStatusLabel->setText("packets: " + QString::number(size) + "/" + QString::number(packets.size()));
}

void MainWindow::acceptPacket(const int index, Packet*) const
{
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

void MainWindow::initSlots()
{
    connect(ui->resetBtn, &QPushButton::clicked, this, &MainWindow::resetCapture);
    connect(ui->startBtn, &QPushButton::clicked, this, &MainWindow::toggleStartBtn);
    connect(ui->interfaceList, &QComboBox::currentIndexChanged, this, &MainWindow::changeInterfaceIndex);
    connect(packetSource, &PacketSource::listen_started, this, &MainWindow::captureInterfaceStarted);
    connect(packetSource, &PacketSource::listen_stopped, this, &MainWindow::captureInterfaceStopped);
    connect(packetSource, &PacketSource::captured, this, &MainWindow::acceptPacket);
    connect(ui->packetsTable, &QTableWidget::clicked, this, &MainWindow::tableItemClicked);
    connect(ui->loadFileBtn, &QPushButton::clicked, this, &MainWindow::loadOfflineFile);
}

void MainWindow::loadOfflineFile() const
{
    QString filename = QFileDialog::getOpenFileName(
        ui->loadFileBtn, "Select a pcap file",
        QDir::homePath(), "pcap file(*.pcap *.pcapng)");

    if (filename.isEmpty()) {
        return;
    }

    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t* interface = open_offline_pcap(filename.toStdString().c_str(), 0, ebuf);
    if (interface == nullptr) {
        QMessageBox::warning(ui->loadFileBtn, "Warning", ebuf);
        return;
    }

    packetSource->set_filename(filename.toStdString());
    packetSource->init(nullptr, interface);
    packetSource->start();
}

void MainWindow::tableItemClicked(const QModelIndex& index)
{
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
            string("type: ").append(packet->get_type()).append("(hex:").append(to_string(packet->get_type_flag())).append(")").c_str())),
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

    int line_count = ceil(static_cast<float>(packet->get_len()) / static_cast<float>(16));
    for (int i = 0; i < line_count; i++) {
        ui->hexTable->insertRow(i);
        ui->hexTable->setRowHeight(i, HEX_TABLE_SIDE_LENGTH);
    }

    int row = 0;
    string content;
    const u_char* payload = packet->get_payload();
    for (int i = 0; i < packet->get_len(); i++) {
        // 收集可见字符和换行，以填充 Text View
        if (char c = static_cast<char>(payload[i]); c == 10 || c == 13) {
            content += c; // 保留换行
        } else {
            if (c > 31 && c < 127) { // ASCII 可见字符
                content += c;
            } else {
                content += ".";
            }
        }

        // 移动行游标
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

    // text 查看器
    ui->plainTextEdit->clear();
    ui->plainTextEdit->setReadOnly(true);
    ui->plainTextEdit->appendPlainText(content.c_str());

    // ascii 查看器
    ui->asciiViewTable->clearContents();
    ui->asciiViewTable->setRowCount(0);

    line_count = ceil(static_cast<float>(packet->get_len()) / static_cast<float>(32));
    for (int i = 0; i < line_count; i++) {
        ui->asciiViewTable->insertRow(i);
        ui->asciiViewTable->setRowHeight(i, HEX_TABLE_SIDE_LENGTH);
    }

    row = 0;
    for (int i = 0; i < packet->get_len(); i += 2) {
        if (i > 0 && i % 32 == 0) {
            row++;
        }

        if (i % 16 == 0 && i % 32 != 0) {
            ui->asciiViewTable->setItem(row, 16, new QTableWidgetItem(" "));
        }

        string c;
        if (payload[i] > 31 && payload[i] < 127) { // 可见字符
            c += payload[i];
        } else {
            c += ".";
        }

        // 一个格子填充两个字符
        if (payload[i + 1] > 31 && payload[i + 1] < 127) { // 可见字符
            c += payload[i + 1];
        } else {
            c += ".";
        }

        // 一个格子填充两个字符，所以应该偏移两格
        int index = i % 32 < 16 ? i % 32 : (i % 32) + 2;
        ui->asciiViewTable->setItem(row, index / 2, new QTableWidgetItem(c.c_str()));
    }
}

void MainWindow::initInterfaceList()
{
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

        LOG(INFO) << std::format("lookup dev: {}", dev->name);
        dev = dev->next;
    }
}

void MainWindow::about()
{
    QMessageBox::about(this, "About WireDolphin", "a Simple Wireshark For learning C++ and QT");
}

void MainWindow::activateStatsWindow() const
{
    // 确保窗口显示
    statsWindow->show();
    // 提升窗口显示层级到顶层
    statsWindow->raise();
    // 获得焦点
    statsWindow->activateWindow();
}

void MainWindow::saveAsPcap()
{
    if (packetSource->get_dump_filename().empty()) {
        QMessageBox::warning(this, "", "no dump file");
        return;
    }

    string basedir = QStandardPaths::standardLocations(QStandardPaths::DocumentsLocation)[0]
                         .toStdString();

    QString fileName = QFileDialog::getSaveFileName(this, "Save document", basedir.c_str(), "*.pcap");
    if (!fileName.isEmpty()) {
        std::filesystem::rename(packetSource->get_dump_filename(), fileName.toStdString());
        trayIcon->showMessage("INFO", std::format("Save complete: {}", fileName.toStdString()));
    }
}

void MainWindow::initMenus()
{
    // 加载本地 pcap 文件，该功能可以调用，但会立即崩溃
    loadFileAct = new QAction(tr("&Load offline .pcap"), this);
    loadFileAct->setShortcuts(QKeySequence::Open);
    connect(loadFileAct, &QAction::triggered, this, &MainWindow::loadOfflineFile);

    // 本质上就是把捕获的 pcap 文件移动到新路径
    saveAct = new QAction(tr("&Dump File"), this);
    saveAct->setShortcuts(QKeySequence::SaveAs);
    connect(saveAct, &QAction::triggered, this, &MainWindow::saveAsPcap);

    dumpFilename = new QAction("Wait Start.", this);
    dumpFilename->setDisabled(true);

    // 打开统计视图
    statsAct = new QAction(tr("&Statistics"), this);
    connect(statsAct, &QAction::triggered, this, &MainWindow::activateStatsWindow);

    // 两个 About
    aboutAct = new QAction(tr("&About"), this);
    connect(aboutAct, &QAction::triggered, this, &MainWindow::about);
    aboutQtAct = new QAction(tr("About &Qt"), this);
    connect(aboutQtAct, &QAction::triggered, QApplication::aboutQt);

    // 文件菜单
    // 如果 Action 在默认菜单列已经实现，则不会显示该 Action
    fileMenu = new QMenu(tr("&File"), this);
    fileMenu->addAction(loadFileAct);
    fileMenu->addAction(saveAct);
    fileMenu->addAction(saveAct);
    fileMenu->addSeparator();
    fileMenu->addAction(dumpFilename);

    // Help 在 Mac 下会被合并到默认菜单列
    helpMenu = new QMenu(tr("&Help"), this);
    helpMenu->addAction(aboutAct);
    helpMenu->addAction(aboutQtAct);

    windowMenu = new QMenu(tr("&Window"), this);
    windowMenu->addAction(statsAct);

    menuBar()->addMenu(fileMenu);
    menuBar()->addMenu(windowMenu);
}
