#pragma once
#include <QWidget>
#include <set>

QT_BEGIN_NAMESPACE
namespace Ui {
class PreferencesWindow;
}
QT_END_NAMESPACE

class PreferencesWindow : public QWidget {
    Q_OBJECT

public:
    explicit PreferencesWindow(QWidget* parent = nullptr);
    void openDBFileSelection() const;
    ~PreferencesWindow() override;
    void onLangListChange(int index) const;

private:
    Ui::PreferencesWindow* ui;
};
