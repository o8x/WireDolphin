#ifndef STATS_H
#define STATS_H

#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui {
class stats;
}
QT_END_NAMESPACE

class StatsWindow : public QWidget {
    Q_OBJECT

public:
    explicit StatsWindow(QWidget* parent = nullptr);
    ~StatsWindow() override;

private:
    Ui::stats* ui;
};

#endif // STATS_H
