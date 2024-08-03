#include <iostream>
#include <QMessageBox>

#include "mainwindow.h"
#include "interface.h"
#include "packetsource.h"
#include "ui_MainWindow.h"

using namespace std;

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    packets = vector<Packet*>();
    packetHandler = new PacketSource(this, &packets);

    initWidgets();
    initInterfaceList();
    initSlots();
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
}

void MainWindow::changeInterfaceIndex(int index) const {
    ui->startBtn->setDisabled(index == 0);
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

void MainWindow::initWidgets() const {
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

    const QFont font("", 12, QFont::Normal);
    const QStringList title = {
        "NO.", "Time", "Source", "Destination", "Protocol", "Len", "Info",
    };
    ui->packetsTable->setColumnCount(title.length());
    ui->packetsTable->setFont(font);
    ui->packetsTable->setRowCount(0);
    ui->packetsTable->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    ui->packetsTable->setColumnWidth(0, 50);
    ui->packetsTable->setColumnWidth(1, 120);
    ui->packetsTable->setColumnWidth(2, 110);
    ui->packetsTable->setColumnWidth(3, 110);
    ui->packetsTable->setColumnWidth(4, 60);
    ui->packetsTable->setColumnWidth(5, 60);
    ui->packetsTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    ui->packetsTable->setHorizontalHeaderLabels(title);
    ui->packetsTable->setShowGrid(false);
    ui->packetsTable->verticalHeader()->setVisible(false);
    ui->packetsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // 树视图
    ui->layerTree->expandAll();
    ui->layerTree->setHeaderLabel("layers");
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

    ui->packetsTable->insertRow(ui->packetsTable->rowCount());
    // ui->packetsTable->setRowHeight(count, 18);
    ui->packetsTable->setItem(index, 0, new QTableWidgetItem(QString::number(index)));
    ui->packetsTable->setItem(index, 1, new QTableWidgetItem(packet->get_time().substr(11).c_str()));
    ui->packetsTable->setItem(index, 2, new QTableWidgetItem(packet->get_host_src().c_str()));
    ui->packetsTable->setItem(index, 3, new QTableWidgetItem(packet->get_host_dst().c_str()));
    ui->packetsTable->setItem(index, 4, new QTableWidgetItem(packet->get_type().c_str()));
    ui->packetsTable->setItem(index, 5, new QTableWidgetItem(QString::number(packet->get_len())));
    ui->packetsTable->setItem(index, 6, new QTableWidgetItem(packet->get_info().c_str()));

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
    if (packet->get_ip_version() == 6) {
        ipv6_header* v6 = packet->get_ipv6();
        networkTree->addChildren({
            new QTreeWidgetItem(
                QStringList(string("version: ipv6").c_str())),
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
                QStringList(string("version: ipv").append(to_string((v4->version_ihl & 0xf0) >> 4)).c_str())),
            new QTreeWidgetItem(
                QStringList(string("source: ").append(packet->get_host_src()).c_str())),
            new QTreeWidgetItem(
                QStringList(string("destination: ").append(packet->get_host_dst()).c_str())),
            new QTreeWidgetItem(
                QStringList(string("ihl: ").append(to_string(v4->version_ihl & 0xf)).c_str())),
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

    transportTree = new QTreeWidgetItem(ui->layerTree);
    transportTree->setText(0, "transport");
    transportTree->setExpanded(true);
    transportTree->addChildren({
        new QTreeWidgetItem(QStringList(string("[x] analysis not supported").c_str())),
    });

    applicationTree = new QTreeWidgetItem(ui->layerTree);
    applicationTree->setText(0, "application");
    applicationTree->setExpanded(true);
    applicationTree->addChildren({
        new QTreeWidgetItem(QStringList(string("[x] analysis not supported").c_str())),
    });
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
