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
}

void MainWindow::changeInterfaceIndex(int index) {
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

    QFont font("", 12, QFont::Normal);
    QStringList title = {"NO.", "Time", "Protocol", "Len", "Info",};
    ui->packetsTable->setColumnCount(title.length());
    ui->packetsTable->setFont(font);
    ui->packetsTable->setRowCount(0);
    ui->packetsTable->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    ui->packetsTable->setColumnWidth(0, 60);
    ui->packetsTable->setColumnWidth(1, 200);
    ui->packetsTable->setColumnWidth(2, 50);
    ui->packetsTable->setColumnWidth(3, 50);
    ui->packetsTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    ui->packetsTable->setHorizontalHeaderLabels(title);
    ui->packetsTable->setShowGrid(false);
    ui->packetsTable->verticalHeader()->setVisible(false);
    ui->packetsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
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
    ui->packetsTable->setItem(index, 1, new QTableWidgetItem(packet->get_time().data()));
    ui->packetsTable->setItem(index, 2, new QTableWidgetItem(packet->get_protocol().c_str()));
    ui->packetsTable->setItem(index, 3, new QTableWidgetItem(QString::number(packet->get_len())));
    ui->packetsTable->setItem(index, 4, new QTableWidgetItem(packet->get_info().c_str()));

    updateCaptureStatusLabel();
}

void MainWindow::initSlots() {
    connect(ui->resetBtn, &QPushButton::clicked, this, &MainWindow::resetCapture);
    connect(ui->startBtn, &QPushButton::clicked, this, &MainWindow::toggleStartBtn);
    connect(ui->interfaceList, &QComboBox::currentIndexChanged, this, &MainWindow::changeInterfaceIndex);
    connect(packetHandler, &PacketSource::listen_started, this, &MainWindow::captureInterfaceStarted);
    connect(packetHandler, &PacketSource::listen_stopped, this, &MainWindow::captureInterfaceStopped);
    connect(packetHandler, &PacketSource::packet_pushed, this, &MainWindow::acceptPacket);
}

void MainWindow::initInterfaceList() {
    if (pcap_findalldevs(&allDevs, error_buffer) != 0) {
        ui->interfaceList->addItem(QString::fromStdString(error_buffer));
        return;
    }

    ui->interfaceList->addItem(QString::fromStdString("Choose interface"));
    if (allDevs == NULL) {
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
