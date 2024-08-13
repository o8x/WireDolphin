WireDolphin
======

使用 QT6 制作的简易 WireShark

## Feature List

- [x] 基本框架界面
- [x] 表格和树界面可改变宽度
- [x] libpcap 抓包
- [x] 优化 libpcap 性能
- [x] 1000M 网络不丢包
- [x] 二层协议解析（数据链路层，以太网）
- [x] 二层协议详情树
- [x] 三层协议解析（网络层，IPv4/IPv6/ICMP/ARP）
- [x] 三层协议详情树
- [x] 四层协议解析（传输层，TCP/UDP）
- [x] 四层协议详情树
- [x] 识别 TCP Flag、Seq、NextSeq、Window 等
- [x] 日志模块
- [x] ARP 解析
- [x] HTTP 解析
- [x] 表格根据协议内容按不同颜色展示
- [x] 支持导入 pcap 并进行分析
- [x] 软件图标
- [x] 生成可分发 dmg
- [x] 代码自动化格式化工具 (clang-format)
- [ ] ICMP 解析
- [ ] DNS 解析
- [ ] TCP 流跟踪
- [ ] HTTP 流跟踪
- [ ] HTTPS 握手识别
- [ ] 会话交易分析
- [ ] 代理协议解析(socks5)
- [ ] 网卡、会话、IP维度的指标统计
- [ ] TCP 分段丢失、乱序、重传识别
- [ ] VLAN 识别（包含多层）
- [ ] 支持数据包对指定网卡重放
- [ ] 表格组件性能问题（目前200M左右带宽界面会无响应）
- [ ] 跨平台支持（WinPcap）
