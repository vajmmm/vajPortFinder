# PortFinder - 高性能网络扫描工具

一个基于Go语言开发的多功能网络扫描工具，支持多种扫描模式和OS指纹识别功能。

## 🚀 特性

- **多种扫描模式**：支持TCP、UDP、SYN、FIN、ACK等多种扫描技术
- **OS指纹识别**：基于nmap-os-db数据库的操作系统探测
- **防火墙检测**：ACK扫描可以检测防火墙过滤规则
- **高性能**：多线程并发扫描，支持大规模网络探测
- **灵活配置**：支持单IP、IP范围、CIDR网络段扫描
- **详细输出**：提供详细的扫描结果和调试信息

## 📋 系统要求

- **操作系统**：Linux（由于使用原始套接字，需要root权限）
- **Go版本**：Go 1.16+
- **权限**：需要root权限运行

## 🔧 安装

```bash
# 克隆项目
git clone <repository-url>
cd portfinder

# 编译
go build -o portfinder main.go

# 或者直接运行
go run main.go
```

## 📖 使用方法

### 基本语法
```bash
sudo ./portfinder <目标IP> [端口列表] <扫描模式>
```

### 扫描模式

| 模式 | 描述 | 用途 |
|------|------|------|
| `full` | 全连接扫描 | 最准确的端口状态检测 |
| `syn` | SYN扫描 | 快速隐蔽的端口扫描 |
| `udp` | UDP扫描 | UDP服务发现 |
| `fin` | FIN扫描 | 绕过简单防火墙 |
| `fin-advanced` | 高级FIN扫描 | 增强的FIN扫描模式 |
| `ack` | ACK扫描 | 防火墙规则检测 |
| `os` | OS指纹识别 | 操作系统类型探测 |

### 📝 使用示例

#### 端口扫描
```bash
# SYN扫描单个IP的常见端口
sudo ./portfinder 192.168.1.1 80,443,22,21,25 syn

# 全连接扫描端口范围
sudo ./portfinder 192.168.1.1 1-1000 full

# UDP扫描
sudo ./portfinder 192.168.1.1 53,67,68,161 udp

# 扫描网络段
sudo ./portfinder 192.168.1.0/24 80,443 syn

# ACK扫描检测防火墙
sudo ./portfinder 192.168.1.1 1-65535 ack
```

#### OS指纹识别
```bash
# 单个IP的OS探测
sudo ./portfinder 192.168.1.1 os
