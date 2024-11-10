// You may need to build the project (run Qt uic code generator) to get "ui_PreferencesWindow.h" resolved

#include "preferenceswindow.h"

#include "conf.h"
#include "locale.hpp"
#include "ui_PreferencesWindow.h"

#include <QFileDialog>
#include <iostream>

PreferencesWindow::PreferencesWindow(QWidget* parent)
    : QWidget(parent)
    , ui(new Ui::PreferencesWindow)
{
    ui->setupUi(this);
    ui->languageLabel->setText(TL_COLON(TL_LANGUAGE).c_str());

    for (const auto& [key, value] : lc::languages) {
        ui->languageList->addItem(value.c_str());
    }

    ui->dbValue->setText(DB_FILE);
    ui->languageList->setCurrentIndex(conf::preferences("Language")->IntText());

    connect(ui->dbSelectBtn, &QPushButton::clicked, this, &PreferencesWindow::openDBFileSelection);
    connect(ui->languageList, &QComboBox::currentIndexChanged, this, &PreferencesWindow::onLangListChange);
}

void PreferencesWindow::openDBFileSelection() const
{
    const QString name = QFileDialog::getSaveFileName(
        ui->dbSelectBtn, TL_SELECT_PCAP_FILE.c_str(),
        conf::local_data_location().c_str(), "sqlite file(*.sqlite3 *.db)");

    if (name.isEmpty()) {
        return;
    }

    std::string filename = name.toStdString();

    if (const std::string_view sv(filename); !sv.ends_with(".sqlite3") && !sv.ends_with(".db")) {
        filename.append(".sqlite3");
    }

    // 将数据库文件备份后移动到新位置
    std::filesystem::copy_file(DB_FILE, std::string(DB_FILE).append(".backup"));
    std::filesystem::rename(DB_FILE, filename);

    ui->dbValue->setText(filename.c_str());
    conf::preferences("Sqlite3Database")->SetText(filename.c_str());
    conf::update();
}

PreferencesWindow::~PreferencesWindow()
{
    delete ui;
}

void PreferencesWindow::onLangListChange(const int index) const
{
    conf::preferences("Language")->SetText(index);
    conf::update();
}
