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
- [ ] #include #define 自动化格式化工具
- [ ] ARP、ICMP、HTTP、DNS、socks5解析
- [ ] HTTPS client hello 识别
- [ ] 识别 TCP 分段丢失、乱序、重传
- [ ] 识别 TCP、HTTP、更多协议的流
- [ ] 网卡、会话、IP维度的统计能力
- [x] 表格根据协议内容按不同颜色展示
- [ ] 识别 VLAN
- [ ] 支持导入 pcap 并进行分析
- [ ] 支持数据包对指定网卡重放
- [ ] 表格组件性能问题（目前瞬间70万数据界面会无响应）
- [ ] 跨平台支持（WinPcap）
