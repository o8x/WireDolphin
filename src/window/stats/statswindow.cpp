#include "statswindow.h"
#include "ui_statswindow.h"
#include <QChartView>
#include <QLineSeries>
#include <QWindow>
#include <iostream>

StatsWindow::StatsWindow(QWidget* parent)
    : QWidget(parent)
    , ui(new Ui::stats)
{
    ui->setupUi(this);

    setWindowTitle("Statistics");
    setWindowFlag(Qt::WindowCloseButtonHint);
    setFixedSize(this->width(), this->height());
}

StatsWindow::~StatsWindow()
{
    delete ui;
}
