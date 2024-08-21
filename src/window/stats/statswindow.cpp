#include "statswindow.h"
#include "ui_statswindow.h"

#include <glog/logging.h>
#include <iostream>

StatsWindow::StatsWindow(QWidget* parent)
    : QWidget(parent)
    , ui(new Ui::stats)
    , mTag1(0)
    , mTag2(0)
{
    ui->setupUi(this);
}

void StatsWindow::initGraph()
{
    connect(packetSource, &PacketSource::captured, this, &StatsWindow::acceptPacket);

    ui->networkPlot->axisRect()->setMinimumSize(300, 180);
    ui->networkPlot->setMinimumSize(ui->tabWidget->width(), ui->tabWidget->height());
    ui->networkPlot->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom | QCP::iSelectPlottables);

    ui->networkPlot->yAxis->setTickLabels(false);
    connect(ui->networkPlot->yAxis2, SIGNAL(rangeChanged(QCPRange)), ui->networkPlot->yAxis, SLOT(setRange(QCPRange)));
    ui->networkPlot->yAxis2->setVisible(true);
    ui->networkPlot->axisRect()->addAxis(QCPAxis::atRight);
    ui->networkPlot->axisRect()->axis(QCPAxis::atRight, 0)->setPadding(30);
    ui->networkPlot->axisRect()->axis(QCPAxis::atRight, 1)->setPadding(30);

    mGraph1 = ui->networkPlot->addGraph(ui->networkPlot->xAxis, ui->networkPlot->axisRect()->axis(QCPAxis::atRight, 0));
    mGraph2 = ui->networkPlot->addGraph(ui->networkPlot->xAxis, ui->networkPlot->axisRect()->axis(QCPAxis::atRight, 1));
    mGraph1->setPen(QPen(QColor(250, 120, 0)));
    mGraph2->setPen(QPen(QColor(0, 180, 60)));

    mTag1 = new AxisTag(mGraph1->valueAxis());
    mTag1->setPen(mGraph1->pen());
    mTag2 = new AxisTag(mGraph2->valueAxis());
    mTag2->setPen(mGraph2->pen());

    this->resize(450, 700);

    connect(&mDataTimer, &QTimer::timeout, this, &StatsWindow::timerSlot);
}

StatsWindow::~StatsWindow()
{
    delete ui;
}

void StatsWindow::timerSlot()
{
    mGraph1->addData(mGraph1->dataCount(), packetNum);
    mGraph2->addData(mGraph2->dataCount(), tcpPacketNum);

    ui->networkPlot->xAxis->rescale();
    mGraph1->rescaleValueAxis(false, true);
    mGraph2->rescaleValueAxis(false, true);
    ui->networkPlot->xAxis->setRange(ui->networkPlot->xAxis->range().upper, 100, Qt::AlignRight);

    double graph1Value = mGraph1->dataMainValue(mGraph1->dataCount() - 1);
    double graph2Value = mGraph2->dataMainValue(mGraph2->dataCount() - 1);
    mTag1->updatePosition(graph1Value);
    mTag2->updatePosition(graph2Value);
    mTag1->setText(QString::number(graph1Value));
    mTag2->setText(QString::number(graph2Value));

    ui->networkPlot->replot();
    packetNum = 0;
    tcpPacketNum = 0;
}

void StatsWindow::acceptPacket(const int index, const Packet* packet)
{
    packetNum++;

    if (packet->get_type() == "TCP" || packet->get_type() == "TCP6") {
        tcpPacketNum++;
    }
}

bool StatsWindow::event(QEvent* event)
{
    // 失去焦点时，隐藏窗体。
    // QEvent::Leave 可以实现类似的效果，但只要鼠标从窗体中出去，就会立即隐藏
    if (event->type() == QEvent::WindowDeactivate) {
        mDataTimer.stop();
        hide();
    }

    if (event->type() == QEvent::WindowActivate) {
        mDataTimer.start(1000);
    }

    return QWidget::event(event);
}
