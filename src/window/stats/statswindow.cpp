#include "statswindow.h"
#include <iostream>
#include <QWindow>
#include <QChartView>
#include <QLineSeries>
#include "ui_statswindow.h"

StatsWindow::StatsWindow(QWidget* parent) :
    QWidget(parent), ui(new Ui::stats) {
    ui->setupUi(this);

    setWindowTitle("Statistics");
    setWindowFlag(Qt::WindowCloseButtonHint);
    setFixedSize(this->width(), this->height());
}

StatsWindow::~StatsWindow() {
    delete ui;
}
