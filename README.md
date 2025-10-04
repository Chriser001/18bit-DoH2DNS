# DNS over HTTPS Proxy Server

<div align="center">
  <p><strong>Built with ❤️ by code-supernova & Windsurf</strong></p>
  <p>
    <img src="https://img.shields.io/badge/code--supernova-AI%20Assistant-8A2BE2?style=for-the-badge&logo=openai&logoColor=white" alt="code-supernova">
    <img src="https://img.shields.io/badge/Windsurf-IDE-007ACC?style=for-the-badge&logo=visual-studio-code&logoColor=white" alt="Windsurf">
  </p>
</div>

[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

一个高性能的 DNS over HTTPS (DoH) 代理服务器，具有智能负载均衡和缓存功能。

## ✨ 特性

- 🚀 **高性能**：基于 Tokio 异步运行时，支持高并发请求处理
- ⚖️ **智能负载均衡**：基于响应时间的加权轮询算法，自动选择最佳服务器
- 💾 **内存缓存**：LRU缓存机制，有效减少重复查询
- 🔄 **动态刷新**：自动刷新 DoH 服务器IP地址和重新计算权重
- 🛡️ **容错机制**：失败重试和自动故障转移
- 📊 **实时监控**：详细的响应时间和性能日志

## 🏗️ 架构原理

### 加权负载均衡
```
权重计算公式：
新权重 = 旧权重 + (超时时间 - 响应时间) / 超时时间 × 权重提升因子

特点：
- 快速响应的服务器获得更高权重
- 慢速服务器权重自动衰减
- 每5分钟自动重新计算权重
```

### 缓存机制
- 3000条LRU缓存容量
- 1小时TTL缓存时间
- 自动清理过期条目

## 📋 系统要求

- Rust 1.70 或更高版本
- Linux/macOS/Windows

## 🚀 安装使用

### 1. 克隆项目
```bash
git clone <repository-url>
cd doh-proxy
```

### 2. 构建项目
```bash
cargo build --release
```

### 3. 运行服务器
```bash
# 直接运行
./target/release/doh-proxy

# 或者后台运行
nohup ./target/release/doh-proxy > doh-proxy.log 2>&1 &
```

### 4. 测试代理
```bash
# 使用dig测试
dig @127.0.0.1 www.google.com

# 使用nslookup测试
nslookup www.google.com 127.0.0.1

# 使用host命令测试
host www.google.com 127.0.0.1
```

## ⚙️ 配置说明

### 监听地址
- 默认监听 `0.0.0.0:53` (所有接口，端口53)
- 支持IPv4和IPv6

### 上游服务器
- 默认使用 `doh.18bit.cn` 的多个IP地址
- 自动解析和负载均衡

### 定时任务
- **权重重新计算**：每5分钟
- **IP地址刷新**：每12小时

### 缓存配置
- **容量**：3000条目
- **TTL**：3600秒（1小时）
- **算法**：LRU（最近最少使用）

## 📊 性能参数

| 参数 | 值 | 说明 |
|------|-----|------|
| 最大重试次数 | 3 | 同一服务器失败后切换 |
| 响应超时 | 1000ms | 超过此时间认为失败 |
| 权重提升因子 | 0.2 | 快速响应的奖励倍数 |
| 权重衰减因子 | 0.7 | 慢速响应的惩罚倍数 |
| 最小权重 | 0.3 | 防止权重过低 |
| 最大权重 | 1.0 | 权重上限 |

## 🔍 日志格式

```
2024-01-01 12:00:00 +0800: 1.1.1.1 - www.google.com - 150.23ms
```

日志字段说明：
- **时间戳**：响应完成时间
- **服务器IP**：实际处理请求的服务器
- **域名**：查询的域名
- **响应时间**：毫秒为单位

## 🛠️ 开发调试

### 查看缓存状态
```bash
# 程序运行时会显示缓存命中日志
# 如：使用缓存的响应会快速返回
```

### 性能调优
```bash
# 增加缓存容量
const CACHE_SIZE: usize = 5000;

# 调整权重计算参数
const WEIGHT_BOOST_FACTOR: f64 = 0.3;
const WEIGHT_DECAY_FACTOR: f64 = 0.6;
```

## 🐛 常见问题

### Q: 为什么会出现"reply from unexpected source"错误？
A: 早期版本的端口处理有问题，已在最新版本中修复。确保使用最新编译版本。

### Q: 如何查看程序运行状态？
A: 程序会输出详细的日志，包括每个请求的处理情况和服务器状态。

### Q: 支持哪些DNS查询类型？
A: 支持所有标准DNS查询类型，包括A、AAAA、CNAME、MX等。

## 🤝 贡献指南

欢迎提交Issue和Pull Request！请确保：

1. 代码通过所有测试
2. 添加相应的单元测试
3. 更新文档

## 📜 许可证

MIT License - 详见[LICENSE](LICENSE)文件

## 🙏 致谢

- [Tokio](https://tokio.rs/) - 异步运行时
- [reqwest](https://github.com/seanmonstar/reqwest) - HTTP客户端
- [dns-parser](https://github.com/bluecatengineering/dns-parser) - DNS解析库

---

⭐ 如果这个项目对你有帮助，请给个Star！
