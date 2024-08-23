#pragma once

#include "packet.h"
#include <QThread>
#include <pcap.h>
#include <queue>

// 更新表格超时周期
#define DEFAULT_QUEUE_UPDATE_TIMEOUT_MS 10
// 数字越小，小流量更新频率越快，实时性越高
#define DEFAULT_PERIOD_AVERAGE 5
// 10ms 内更新 100 条，一秒就会更新1万条，表格可能来不及更新就会卡死
#define AVERAGE_PERIOD(v) \
    (v > 100 ? v * 5 : (v > 50 ? v * 3 : (v > DEFAULT_PERIOD_AVERAGE ? v : DEFAULT_PERIOD_AVERAGE)))

typedef struct packetsource_state {
    string interface_name;
    string state;
    string dump_filename;
} PACKETSOURCE_STATE;

class PacketSource final : public QObject {
    Q_OBJECT

    /**
     * 全局互斥锁
     */
    std::mutex mtx;
    /**
     * 包队列
     * 用于在捕获线程和渲染线程之间转移包
     * 捕获后的包会先到该队列，每隔一段时间会被消费和传递到UI线程进行表格渲染
     */
    std::queue<Packet*> bridge;
    /*
     * 存储捕获的所有的包
     * 要在开始或重置时清空，否则将内存泄漏
     */
    std::vector<Packet*> history;
    /*
     * 记录队列上一次被清空的时间
     */
    std::chrono::steady_clock::time_point last_access;
    /**
     * 时间段内捕获的包的平均数
     * 做到推送的行数不恒定，流量越大推送频率越低，但一次推送的数量越多
     */
    int period_average = DEFAULT_PERIOD_AVERAGE;
    /**
     * 填充桥的线程
     */
    std::thread fill_thread;
    /**
     * 消费桥的线程
     * 都在析构和停止捕获时进行 join
     */
    std::thread consume_thread;
    /**
     * 捕获的接口的 pcap 实例
     */
    pcap_t* interface = nullptr;
    /**
     * 捕获的接口的设备实例，目前只是从里面取出名字，没有其他用途
     */
    pcap_if_t* device = nullptr;
    /**
     * 当前一次捕获到的包暂存文件的文件名
     * 当启动捕获时，该文件会被删除和重建
     * 当选择 Menu 中的 Dump File 时将会被移动到用户选择的目录
     */
    string dump_filename;
    /**
     * pcap 的写入 pcap 文件的句柄
     */
    pcap_dumper_t* dump_handler = nullptr;
    /**
     * 如果当前并不是实时捕获，而是打开了一个文件，就会填充改文件名
     */
    string filename;
    /**
     * 控制是否继续接收和处理包
     */
    bool running = false;

    void capture_packet();
    void dump_flush(const pcap_pkthdr*, const u_char*) const;
    static int parse_header(const u_char**, Packet*& p);
    void consume_queue();

signals:
    void listen_started(PACKETSOURCE_STATE) const;
    void listen_stopped(PACKETSOURCE_STATE) const;
    void captured(size_t, Packet*);
    void capture_cycle_flush(size_t, size_t);

public:
    explicit PacketSource();
    ~PacketSource();

    void free_wait();
    void set_filename(const string& filename);
    void start_on_interface(pcap_if_t* device, pcap_t* interface);

    [[nodiscard]] string get_filename() const;
    [[nodiscard]] pcap_t* get_interface() const;void free_history();
    [[nodiscard]] string get_dump_filename() const;
    [[nodiscard]] size_t packet_count() const;
    [[nodiscard]] Packet* peek(int index) const;
};
