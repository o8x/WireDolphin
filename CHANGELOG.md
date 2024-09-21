# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- 引入 PcapPlusPlush 以支持 DPDK
- 支持外挂采集数据的 Agent，通过 zmq 传输抓包数据
- 分离前后端，QT 只做展示端
- 流量分级（可接受，安全，未分级，不安全）
- Top 主机
- Top 应用
- Top 会话
- 活动流（应用，连接状态、类型，掩码等维度的筛选）
- 主机监控
- 网内扫描
- 数据警告（流，主机，会话，主机监控，系统等维度）
- 主机纳管（机器名，操作系统，网段，活动流，地理位置，评分等统计）
- 接口流量记录
- 统计视图（初步建设已完成，暂时搁置）
- OOP with PImpl 改造
- ICMP 解析
- DNS 解析
- TCP 流跟踪
- HTTP 流跟踪
- HTTPS 握手识别
- 会话交易分析
- 代理协议解析(socks5)
- 网卡、会话、IP维度的指标统计
- TCP 分段丢失、乱序、重传识别
- VLAN 识别（包含多层）
- 支持数据包对指定网卡重放
- 跨平台支持（WinPcap）
- TableWidget 改成自定义 TableView，实现手动影响表格渲染，彻底解决表格渲染性能问题

## [v0.3.0] - 2024-08-23

### Added

- 自动保留和清理和每次自启动后捕获的包
- 允许把包保存到本地
- 新增捕获周期结束事件推送

### Changed

- 捕获周期结束事件时更新界面，但 TableWidget 不支持手动的视图更新，因此只实现了状态栏的自动更新和表格自动滚动
- 解决表格组件性能问题（1000M 不丢包不崩溃，但持续抓包会无响应，流量变小一段时间后自动恢复）

## [v0.2.0] - 2024-08-21

### Added

- 自动维护核心配置文件
- 自动记录和恢复主窗口位置、大小
- 基本的 MenuBar 用于展示统计视图
- 接入 glog 日志库
- 编译 release 时自动对 .app 文件签名

## [v0.1.0] - 2024-08-13

### Added

- 基本的框架界面
- 可变宽度、颜色丰富的表格和树界面
- 基于 libpcap 的高性能抓包引擎
- 二层协议解析（数据链路层，以太网）与协议树
- 三层协议解析（网络层，IPv4/IPv6/ICMP/ARP）与协议树
- 四层协议解析（传输层，TCP/UDP）与协议树
- 识别 TCP 包的多种指标
- 多种 Payload 查看视图
- ARP 会话以及 HTTP 请求头解析
- 支持导入 pcap 并进行分析（不稳定）
- 使用AI绘制的软件图标
- dmg 打包脚本
