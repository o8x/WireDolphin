#pragma once

#include <map>
#include <unordered_map>

#define _(name) lc::Locale::translate(name)
#define TL_COLON(s) std::string(s).append(": ")
#define TL_CONCAT(s, s2) std::string(s).append(s2)

#define TL_ON _("on")
#define TL_OFF _("off")
#define TL_WAITING _("waiting")
#define TL_CAPTURED _("captured")
#define TL_DROPPED _("dropped")
#define TL_APP_TITLE _("app:title")
#define TL_PREFERENCES _("Preferences")
#define TL_SNIFFER _("Sniffer")
#define TL_HEX _("hex")
#define TL_HEX_VIEW _("Hex View")
#define TL_ASCII_VIEW _("ASCII View")
#define TL_TEXT_VIEW _("Text View")
#define TL_HOST_TITLE _("host:title")
#define TL_FILTER_EXPRESSION _("filter expression")
#define TL_STOP _("stop")
#define TL_RESET _("Reset")
#define TL_START _("start")
#define TL_LOAD_FILE _("Load File")
#define TL_NO _("NO.")
#define TL_TIME _("Time")
#define TL_SOURCE _("Source")
#define TL_DESTINATION _("Destination")
#define TL_PROTOCOL _("Protocol")
#define TL_LENGTH _("length")
#define TL_INFO _("Info")
#define TL_LAYERS _("layers")
#define TL_LANGUAGE _("language")
#define TL_WARNING _("Warning")
#define TL_FRAME _("frame")
#define TL_TRANSPORT _("transport")
#define TL_DATA_OFFSET _("data offset")
#define TL_CHOOSE_INTERFACE _("Choose Interface")
#define TL_APPLICATION _("application")
#define TL_UNREACHABLE _("Unreachable")
#define TL_TIMESTAMP _("timestamp")
#define TL_ETHERNET_LENGTH _("ethernet length")
#define TL_IPV4_LENGTH _("ipv4 length")
#define TL_DATA_LINK _("data link")
#define TL_TYPE _("type")
#define TL_NETWORK _("network")
#define TL_HARDWARE_TYPE _("hardware type")
#define TL_PROTOCOL_TYPE _("protocol type")
#define TL_HARDWARE_LENGTH _("hardware length")
#define TL_PROTOCOL_LENGTH _("protocol length")
#define TL_OP _("op")
#define TL_SENDER_ETHERNET _("sender ethernet")
#define TL_SENDER_HOST _("sender host")
#define TL_DESTINATION_ETHERNET _("destination ethernet")
#define TL_DESTINATION_HOST _("destination host")
#define TL_VERSION _("version")
#define TL_CLASS _("class")
#define TL_FLOW_LABEL _("flow label")
#define TL_NEXT_HEADER _("next header")
#define TL_HOP_LIMIT _("hop limit")
#define TL_PAYLOAD_LENGTH _("payload length")
#define TL_OPTIONS _("options")
#define TL_HEADER_LENGTH _("header length")
#define TL_SERVICE_TYPE _("service type")
#define TL_IDENTIFIER _("identifier")
#define TL_FRAGMENT_OFFSET _("fragment_offset")
#define TL_TIME_TO_LIVE _("time to live")
#define TL_CHECKSUM _("checksum")
#define TL_TRANSPORT _("transport")
#define TL_SOURCE_PORT _("source port")
#define TL_DESTINATION_PORT _("destination port")
#define TL_SEQ_NUMBER _("seq number")
#define TL_ACK_NO _("ack")
#define TL_DATA OFFSET _("data offset")
#define TL_WINDOW _("window")
#define TL_URGENT _("urgent")
#define TL_FLAGS _("flags")
#define TL_CWR _("CWR")
#define TL_ECE _("ECE")
#define TL_URG _("URG")
#define TL_ACK _("ACK")
#define TL_PSH _("PSH")
#define TL_RST _("RST")
#define TL_SYN _("SYN")
#define TL_FIN _("FIN")
#define TL_TOTAL_LENGTH _("total length")
#define TL_APPLICATION _("application")
#define TL_ANALYSIS_NOT_SUPPORTED _("[x] analysis not supported")
#define TL_SELECT_PCAP_FILE _("Select a pcap file")
#define TL_OPEN _("Open")
#define TL_DUMP _("Dump")
#define TL_STATISTICS _("Statistics")
#define TL_ABOUT _("About")
#define TL_FILE _("File")
#define TL_RECENT_FILES _("Recent Files")
#define TL_CLEAR_RECENT _("Clear Recent")
#define TL_HELP _("Help")
#define TL_WAIT_START _("Wait Start")

namespace lc {

enum Locales {
    LOCAL_ALL,
    LOCAL_ZH_CN,
};

inline std::map<Locales, std::string> languages = {
    { LOCAL_ALL, "en_US" },
    { LOCAL_ZH_CN, "zh_CN" },
};

struct Translation {
    std::string en_US;
    std::string zh_CN;
};

class Locale {
private:
    Locales lc = LOCAL_ALL;

    std::unordered_map<std::string, Translation> locals = {
        { "off", { "off", "已关闭" } },
        { "on", { "on", "运行中" } },
        { "waiting", { "waiting", "等待中" } },
        { "dropped", { "dropped", "已丢弃" } },
        { "captured", { "captured", "已捕获" } },
        { "Sniffer", { "Sniffer", "嗅探" } },
        { "Preferences", { "Preferences", "偏好配置" } },
        { "Open", { "Open", "打开" } },
        { "Dump", { "Dump", "转储" } },
        { "Statistics", { "Statistics", "统计" } },
        { "About", { "About", "关于" } },
        { "File", { "File", "文件" } },
        { "Recent Files", { "Recent Files", "最近打开" } },
        { "Clear Recent", { "Clear Recent", "清除最近打开" } },
        { "Help", { "Help", "帮助" } },
        { "Wait Start", { "Wait Start", "等待启动" } },
        { "Window", { "Window", "窗口" } },
        { "app:title", { "WireDolphin", "智能网络流量分析仪" } },
        { "stop", { "Stop", "停止" } },
        { "start", { "Start", "开始" } },
        { "Reset", { "Reset", "重置" } },
        { "Load File", { "Load File", "加载本地文件" } },
        { "NO.", { "NO.", "编号" } },
        { "Time", { "Time", "时间" } },
        { "Source", { "Source", "源" } },
        { "Destination", { "Destination", "目的地" } },
        { "Protocol", { "Protocol", "协议" } },
        { "Len", { "Len", "长度" } },
        { "hex", { "hex", "十六进制值" } },
        { "filter expression", { "filter expression", "过滤表达式" } },
        { "Info", { "Info", "信息" } },
        { "language", { "language", "语言" } },
        { "layers", { "layers", "层信息" } },
        { "Warning", { "Warning", "警告" } },
        { "frame", { "frame", "网络帧" } },
        { "network", { "network", "网络层" } },
        { "transport", { "transport", "传输层" } },
        { "application", { "application", "应用层" } },
        { "Unreachable", { "Unreachable", "不可达" } },
        { "timestamp", { "timestamp", "时间戳" } },
        { "length", { "length", "载荷长度" } },
        { "ethernet length", { "ethernet length", "以太载荷长度" } },
        { "ipv4 length", { "ipv4 length", "IPv4载荷长度" } },
        { "data link", { "data link", "数据链路层" } },
        { "source", { "source", "源地址" } },
        { "destination", { "destination", "目的地址" } },
        { "type", { "type", "类型" } },
        { "network", { "network", "网络层" } },
        { "protocol", { "protocol", "协议" } },
        { "hardware type", { "hardware type", "硬件类型" } },
        { "protocol type", { "protocol type", "协议类型" } },
        { "hardware length", { "hardware length", "硬件地址长度" } },
        { "protocol length", { "protocol length", "协议长度" } },
        { "op", { "op", "操作" } },
        { "sender ethernet", { "sender ethernet", "源物理地址" } },
        { "sender host", { "sender host", "源主机地址" } },
        { "destination ethernet", { "destination ethernet", "目标物理地址" } },
        { "destination host", { "destination host", "目标主机地址" } },
        { "version", { "version", "版本" } },
        { "class", { "class", "类" } },
        { "flow label", { "flow label", "流标签" } },
        { "next header", { "next header", "下一层协议头" } },
        { "hop limit", { "hop limit", "最大跳转次数限制" } },
        { "payload length", { "payload length", "载荷长度" } },
        { "options", { "options", "选项" } },
        { "header length", { "header length", "协议头长度" } },
        { "service type", { "service type", "服务类型" } },
        { "identifier", { "identifier", "ID" } },
        { "fragment_offset", { "fragment_offset", "分段偏移" } },
        { "time to live", { "time to live", "生存时间" } },
        { "checksum", { "checksum", "校验和" } },
        { "transport", { "transport", "数据传输层" } },
        { "source port", { "source port", "源端口" } },
        { "destination port", { "destination port", "目的端口" } },
        { "seq number", { "seq number", "序列号" } },
        { "ack", { "ack", "应答号" } },
        { "data offset", { "data offset", "数据偏移" } },
        { "window", { "window", "窗口" } },
        { "urgent", { "urgent", "紧急指针" } },
        { "flags", { "flags", "标志" } },
        { "CWR", { "CWR", "拥塞窗口" } },
        { "ECE", { "ECE", "窗口拥塞" } },
        { "URG", { "URG", "紧急" } },
        { "ACK", { "ACK", "应答" } },
        { "PSH", { "PSH", "传输" } },
        { "RST", { "RST", "重置" } },
        { "SYN", { "SYN", "同步" } },
        { "FIN", { "FIN", "完成" } },
        { "Hex View", { "Hex View", "十六进制视图" } },
        { "Text View", { "Text View", "文本视图" } },
        { "ASCII View", { "ASCII View", "阿斯克码视图" } },
        { "total length", { "total length", "总长度" } },
        { "Choose Interface", { "Choose Interface", "选择接口" } },
        { "application", { "application", "应用" } },
        { "[x] analysis not supported", { "[x] 协议分析不受支持", "" } },
        { "Select a pcap file", { "Select a pcap file", "选择一个pcap文件" } },
    };

public:
    static Locale* instance()
    {
        static Locale l;
        return &l;
    }

    static void setLocale(const Locales l)
    {
        instance()->lc = l;
    }

    static std::string translate(const std::string& name)
    {
        return translate(instance()->lc, name);
    }

    static std::string translate(const Locales l, const std::string& name)
    {
        Locale* ins = instance();

        const auto it = ins->locals.find(name);
        if (it == ins->locals.end()) {
            return name;
        }

        std::string str;

        switch (l) {
        case LOCAL_ZH_CN:
            str = it->second.zh_CN;
            break;
        default:
            str = it->second.en_US;
            break;
        }

        if (str.empty()) {
            str = it->second.en_US;
        }

        return str;
    }
};

};
