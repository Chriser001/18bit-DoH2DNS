# 18bit DNS over HTTPS 代理服务器

<div align="center">
  <p><strong>高性能智能DNS代理，支持缓存和负载均衡</strong></p>
  <p>
    <img src="https://img.shields.io/badge/Rust-1.70+-blue.svg" alt="Rust">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
    <img src="https://img.shields.io/badge/VS%20Code-1.90+-007ACC?style=flat&logo=visual-studio-code&logoColor=white" alt="VS Code">
    <img src="https://img.shields.io/badge/GitHub%20Copilot-Enabled-000000?style=flat&logo=github&logoColor=white" alt="GitHub Copilot">
  </p>
  <p>
    <img src="https://img.shields.io/badge/Windsurf-Powered-f8f2e7?style=flat&logo=visual-studio-code&logoColor=white" alt="Windsurf">
    <img src="https://img.shields.io/badge/Code--Supernova-AI%20Assistant-8A2BE2?style=flat&logo=openai&logoColor=white" alt="Code-Supernova">
    <img src="https://img.shields.io/badge/Claude%20Sonnet%203.5-Advanced%20AI-8B5CF6?style=flat&logo=anthropic&logoColor=white" alt="Claude Sonnet 3.5">
  </p>
</div>

## 🚀 项目简介

这是一个高性能的企业级 DNS over HTTPS (DoH) 代理服务器，具备以下核心特性：

- **智能缓存系统**：先进的缓存键生成，支持跨客户端查询去重
- **自适应负载均衡**：基于响应时间的动态权重调整
- **高并发处理**：基于 Tokio 的异步架构
- **实时监控**：Web界面展示详细性能指标

## ✨ 核心特性

### 🎯 智能缓存系统
- **跨客户端缓存共享**：相同域名查询自动去重，避免重复请求
- **LRU缓存算法**：3000条目容量，自适应TTL管理
- **压缩指针支持**：正确处理DNS压缩指针，确保缓存键一致性
- **多级回退机制**：完整解析 → 手动解析 → 原始查询，确保兼容性

### ⚖️ 自适应负载均衡
```
权重更新策略：
- 快速响应：权重提升 (响应时间 < 1000ms)
- 慢速响应：权重衰减 (响应时间 > 1000ms)
- 定期重计算：每小时重新评估服务器权重
```

### 📊 实时监控面板
- **Web界面**：`http://localhost:18080` 实时状态监控
- **性能指标**：缓存命中率、平均响应时间、服务器状态
- **查询日志**：最近查询记录，支持缓存状态显示

### 🛡️ 企业级特性
- **故障转移**：多服务器冗余，自动故障检测
- **动态发现**：自动刷新上游服务器IP地址
- **并发保护**：线程安全的缓存和统计计数器

## 🏗️ 技术架构

### 系统组件
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   DNS客户端     │ -> │   代理服务器     │ -> │   上游DoH服务器  │
│   (各种设备)    │    │   (智能缓存)    │    │   (18bit DoH)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                        ┌─────────────────┐
                        │   监控面板      │
                        │   (Web界面)     │
                        └─────────────────┘
```

### 核心算法

#### 缓存键生成
```rust
// 三层解析策略确保缓存键一致性
fn build_cache_key(query: &[u8]) -> Vec<u8> {
    // 1. 完整DNS报文解析
    // 2. 手动域名解析（支持压缩指针）
    // 3. 原始查询回退（仅清零ID）
}
```

#### 负载均衡权重计算
```rust
// 基于响应时间的自适应权重调整
fn update_weight(response_time: f64, is_success: bool) {
    if is_success && response_time < TIMEOUT {
        // 快速响应获得权重提升
        weight += BOOST_FACTOR * (TIMEOUT - response_time) / TIMEOUT;
    } else {
        // 慢速或失败响应导致权重衰减
        weight *= DECAY_FACTOR;
    }
}
```

## 📋 系统要求

- **Rust**: 1.70.0 或更高版本
- **操作系统**: Linux/macOS/Windows
- **内存**: 推荐 512MB 以上
- **网络**: 支持IPv4和IPv6

## 🚀 快速开始

### 安装依赖
```bash
# 克隆项目
git clone <repository-url>
cd doh-proxy

# 构建项目
cargo build --release
```

### 启动服务
```bash
# 前台运行（推荐用于调试）
./target/release/doh-proxy

# 后台运行
nohup ./target/release/doh-proxy > doh-proxy.log 2>&1 &
```

### 验证服务
```bash
# 使用dig测试DNS代理
dig @127.0.0.1 www.google.com

# 使用nslookup测试
nslookup www.google.com 127.0.0.1

# 检查代理日志
tail -f doh-proxy.log
```

## ⚙️ 配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| 监听端口 | 53 | DNS查询监听端口 |
| 缓存容量 | 10000 | LRU缓存最大条目数 |
| 默认TTL | 8小时 | 缓存条目生存时间 |
| 超时时间 | 1000ms | 请求超时阈值 |
| Hedge延迟 | 1500ms | 第二路请求启动延迟 |
| 权重更新间隔 | 1小时 | 服务器权重重新计算周期 |

### 关键常量定义
```rust
const DEFAULT_TTL: u64 = 28800;          // 默认缓存时间（8小时）
const RESPONSE_TIMEOUT_MS: f64 = 1000.0;  // 响应超时（1秒）
const HEDGE_DELAY_MS: u64 = 1500;        // Hedge延迟（1.5秒）
const WEIGHT_UPDATE_INTERVAL: u64 = 3600; // 权重更新间隔（1小时）
```

## 📊 监控与调试

### Web监控面板
访问 `http://localhost:18080` 查看：
- 实时请求统计和缓存命中率
- 上游服务器性能指标
- 最近查询记录和缓存状态

### 日志格式
```
# 缓存命中日志
2025-10-06 12:00:00 +0800: 8.130.86.134 - example.com - HIT (cached)

# 缓存未命中日志
2025-10-06 12:00:01 +0800: 8.130.86.134 - example.com - 45.23ms

# 缓存存储日志
2025-10-06 12:00:02 +0800: Cached example.com for 4h0m
```

### 调试技巧
```bash
# 查看实时日志
tail -f doh-proxy.log | grep -E "(HIT|MISS|Cached)"

# 监控缓存效果
watch -n 1 "curl -s http://localhost:18080/ | grep -A 5 '缓存命中率'"

# 查看缓存键调试信息
tail -f doh-proxy.log | grep "DEBUG: Cache key"
```

## 🔧 高级配置

### 缓存优化
```rust
// 调整缓存参数
const DEFAULT_TTL: u64 = 14400;          // 缩短缓存时间（4小时）
const MIN_TTL: u64 = 3600;               // 最小缓存时间（1小时）
const MAX_TTL: u64 = 86400;              // 最大缓存时间（24小时）
```

### 性能调优
```rust
// 调整负载均衡参数
const WEIGHT_BOOST_FACTOR: f64 = 0.3;    // 提升权重奖励
const WEIGHT_DECAY_FACTOR: f64 = 0.8;    // 降低权重惩罚
const MIN_WEIGHT: f64 = 0.1;             // 最小权重阈值
const MAX_WEIGHT: f64 = 2.0;             // 最大权重上限
```

## 🐛 故障排除

### 常见问题

**Q: 为什么缓存命中率很低？**
A: 检查缓存键生成是否正确。不同客户端的相同查询应该生成相同的缓存键。

**Q: 如何查看缓存键生成详情？**
A: 日志中会定期显示缓存键生成调试信息，格式为 `DEBUG: Cache key generated for domain: key`

**Q: 为什么某些域名无法缓存？**
A: 可能是DNS压缩指针处理问题。检查日志中的域名解析是否正确。

**Q: 如何调整缓存大小？**
A: 修改 `CACHE_SIZE` 常量并重新编译。建议根据内存情况设置 1000-10000 之间。

### 性能诊断
```bash
# 检查系统资源使用
top -p $(pgrep doh-proxy)

# 查看网络连接
netstat -tuln | grep :53

# 分析日志模式
cat doh-proxy.log | grep -o "HIT\|[0-9]\+\.[0-9]\+ms" | sort | uniq -c
```

## 🤝 开发贡献

欢迎提交 Issue 和 Pull Request！

### 开发环境设置
```bash
# 安装开发依赖
cargo install cargo-watch

# 监听代码变更并自动重新编译
cargo watch -x run

# 运行测试
cargo test

# 检查代码格式
cargo fmt --check
cargo clippy -- -D warnings
```

### 代码结构
```
src/
├── main.rs              # 主程序入口和核心逻辑
├── lib.rs               # 库定义（如果需要）
└── bin/                 # 二进制目标
    └── doh-proxy.rs     # 主程序（如果分离）
```

## 📈 性能基准

### 测试环境
- **硬件**: Intel i5-8250U, 8GB RAM
- **网络**: 100Mbps 宽带
- **测试工具**: dnsperf, queryperf

### 性能指标
- **QPS**: 5000+ (取决于缓存命中率)
- **响应时间**: 缓存命中 < 1ms, 未命中 < 100ms
- **内存使用**: ~50MB (含缓存)
- **CPU使用**: 低负载下 < 10%

## 📜 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- **Tokio** - 高性能异步运行时
- **reqwest** - 可靠的HTTP客户端
- **dns-parser** - 轻量级DNS解析库
- **axum** - 优秀的Web框架

---

⭐ 如果这个项目对你有帮助，请给个 Star！
