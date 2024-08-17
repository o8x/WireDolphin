# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- 表格组件性能问题（目前200M左右带宽界面会无响应）
- 跨平台支持（WinPcap）

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
