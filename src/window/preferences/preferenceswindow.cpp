// You may need to build the project (run Qt uic code generator) to get "ui_PreferencesWindow.h" resolved

#include "preferenceswindow.h"

#include "conf.h"
#include "locale.hpp"
#include "ui_PreferencesWindow.h"

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

    const auto settingConf = conf::instance().core()->FirstChildElement("Preferences");
    const int langChecked = settingConf->FirstChildElement("Language")->IntText();
    ui->languageList->setCurrentIndex(langChecked);

    connect(ui->languageList, &QComboBox::currentIndexChanged, this, &PreferencesWindow::onLangListChange);
}

PreferencesWindow::~PreferencesWindow()
{
    delete ui;
}

void PreferencesWindow::onLangListChange(const int index) const
{
    auto settingConf = conf::instance().core()->FirstChildElement("Preferences");
    settingConf->FirstChildElement("Language")->SetText(index);

    conf::instance().update_core();
}
