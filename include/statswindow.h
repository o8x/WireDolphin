#ifndef STATS_H
#define STATS_H
#include "axistag.h"
#include "packetsource.h"

#include <qcustomplot.h>

QT_BEGIN_NAMESPACE
namespace Ui {
class stats;
}
QT_END_NAMESPACE

class StatsWindow : public QWidget {
    Q_OBJECT

    QPointer<QCPGraph> mGraph1;
    QPointer<QCPGraph> mGraph2;
    AxisTag* mTag1;
    AxisTag* mTag2;
    QTimer mDataTimer;
    void timerSlot();

public:
    explicit StatsWindow(QWidget* parent = nullptr);
    void initGraph();
    ~StatsWindow() override;
    void acceptPacket(const int index, const Packet* packet);
    PacketSource* packetSource;

protected:
    bool event(QEvent* event) override;

private:
    Ui::stats* ui;
    int packetNum;
    int tcpPacketNum;
};

#endif // STATS_H
