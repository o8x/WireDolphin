#include "interface.h"
#include <glog/log_severity.h>
#include <glog/logging.h>
#include <iostream>

pcap_t* open_offline_pcap(const char* name, int tstamp_precision, char* error_buffer)
{
    pcap_t* pc = pcap_open_offline_with_tstamp_precision(name, tstamp_precision, error_buffer);
    if (pc == nullptr) {
        LOG(ERROR) << std::format("open {}, error {}", name, error_buffer);
    }

    return pc;
}

pcap_t* open_interface(const char* device, char* ebuf)
{
    pcap_t* pc;
    int status;
    char* cp;
    int supports_monitor_mode = 0;
    int ndo_snaplen = 0;
    int pflag = 0;
    int Iflag = 0;
    int Bflag = 0;
    int jflag = -1;
    int noBlock = 1;
    int timeout = 100;

    // 无论如何都不会有错误
    // pcap_activate 之后可以获取到 No Such Device
    pc = pcap_create(device, ebuf);

    LOG(INFO) << std::format("create device {}", device);

    status = pcap_set_tstamp_precision(pc, 0);
    if (status != 0) {
        LOG(ERROR) << std::format("{}: Can't set {}second time stamp precision: {}", device, 0, pcap_statustostr(status));
    }

    if (pcap_can_set_rfmon(pc) == 1) {
        supports_monitor_mode = 1;
    } else {
        supports_monitor_mode = 0;
    }

    if (ndo_snaplen) {
        status = pcap_set_snaplen(pc, ndo_snaplen);
        if (status != 0) {
            LOG(ERROR) << std::format("{}: Can't set snapshot length: {}", device, pcap_statustostr(status));
        }
    }

    status = pcap_set_promisc(pc, !pflag);
    if (status != 0) {
        LOG(ERROR) << std::format("{}: Can't set promiscuous mode: {}", device, pcap_statustostr(status));
    }

    if (Iflag) {
        status = pcap_set_rfmon(pc, 1);
        if (status != 0) {
            LOG(ERROR) << std::format("{}: Can't set monitor mode: {}", device, pcap_statustostr(status));
        }
    }

    status = pcap_set_timeout(pc, timeout);
    if (status != 0) {
        LOG(ERROR) << std::format("{}: pcap_set_timeout failed: {}", device, pcap_statustostr(status));
    }

    if (Bflag != 0) {
        status = pcap_set_buffer_size(pc, Bflag);
        if (status != 0) {
            LOG(ERROR) << std::format("{}: Can't set buffer size: {}", device, pcap_statustostr(status));
        }
    }

    if (jflag != -1) {
        status = pcap_set_tstamp_type(pc, jflag);
        if (status < 0) {
            LOG(ERROR) << std::format("{}: Can't set time stamp type: {}", device, pcap_statustostr(status));
        } else if (status > 0) {
            LOG(ERROR) << std::format("When trying to set timestamp type '{}' on {}: {}",
                pcap_tstamp_type_val_to_name(jflag), device, pcap_statustostr(status));
        }
    }

    status = pcap_activate(pc);
    if (status < 0) {
        cp = pcap_geterr(pc);
        if (status == PCAP_ERROR) {
            LOG(ERROR) << std::format("{}", cp);
        } else if (status == PCAP_ERROR_NO_SUCH_DEVICE) {
            LOG(ERROR) << std::format("{}: {} ({})", device, pcap_statustostr(status), cp);
        } else if (status == PCAP_ERROR_PERM_DENIED && *cp != '\0') {
            LOG(ERROR) << std::format("{}: {} ({})", device, pcap_statustostr(status), cp);
        } else {
            LOG(ERROR) << std::format("{}: {}", device, pcap_statustostr(status));
        }

        pcap_close(pc);
        return NULL;
    }

    if (status > 0) {
        cp = pcap_geterr(pc);
        if (status == PCAP_WARNING) {
            LOG(ERROR) << std::format("{}", cp);
        } else if (status == PCAP_WARNING_PROMISC_NOTSUP && *cp != '\0') {
            LOG(ERROR) << std::format("{}: {}\n({})", device, pcap_statustostr(status), cp);
        } else {
            LOG(ERROR) << std::format("{}: {}", device, pcap_statustostr(status));
        }
    }

    if (noBlock != -1) {
        char errbuf[PCAP_ERRBUF_SIZE];

        if (pcap_setnonblock(pc, 1, errbuf) != 0) {
            LOG(ERROR) << std::format("{}: {}", device, errbuf);
        }
    }

    return pc;
}

string get_dlt_name(pcap_t* pc)
{
    int dlt = pcap_datalink(pc);

    return pcap_datalink_val_to_name(dlt);
}

string get_dlt_desc(pcap_t* pc)
{
    int dlt = pcap_datalink(pc);

    return pcap_datalink_val_to_description(dlt);
}

void print_stat_info(pcap_t* inet, const size_t packet_num, chrono::time_point<chrono::steady_clock> time_start)
{
    pcap_stat stats {};
    pcap_stats(inet, &stats);

    auto duration = std::chrono::high_resolution_clock::now() - time_start;

    // 将时长转换为需要的单位，这里以秒为例
    auto duration_in_seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();

    // 开始时间和结束时间
    std::cout << "> " << packet_num << " captured in " << duration_in_seconds << " seconds" << std::endl;
    std::cout << "> " << stats.ps_recv << " received by filter" << std::endl;

    if (stats.ps_ifdrop > 0) {
        std::cout << "> " << stats.ps_ifdrop << " dropped by interface" << std::endl;
    }

    if (stats.ps_drop > 0) {
        std::cout << "> " << stats.ps_drop << " dropped by kernel" << std::endl;
    }

    std::cout << "..." << std::endl;
}
