use tokio::net::UdpSocket;
use reqwest::Client;
use lru::LruCache;
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use dns_parser::{Builder, Packet, QueryType};
use chrono::Local;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{interval, Duration};
use std::sync::atomic::{AtomicUsize, Ordering};
use axum::{
    routing::get,
    Router,
    extract::State,
    response::Html,
};
use serde::Serialize;


// 解析黑名单：这些域名及其子域名将被直接拒绝，不进行DoH解析
const DOMAIN_BLACKLIST: &[&str] = &[
    "tdum.alibaba.com",
    "jddebug.com",
    "ios.rqd.qq.com",
    "beacon.qq.com",
    "h.trace.qq.com",
    "snowflake.qq.com",
    "oth.str.mdt.qq.com",
    "tpstelemetry.tencent.com",
    "ias.tencent-cloud.net",
    "rmonitor.qq.com",
    "teg.tencent-cloud.net",
    "dns.weixin.qq.com.cn",
    "aliyunga0018.com",
    "umdcv4.taobao.com",
    "mmstat.com",
    "sentry.io",
    "app-analytics-services.com",
    "xp.apple.com"
  ];

// 检查域名是否在黑名单中（支持子域名匹配）
fn is_domain_blocked(domain: &str) -> bool {
    DOMAIN_BLACKLIST.iter().any(|&blocked| {
        // 精确匹配
        if domain == blocked {
            return true;
        }
        // 子域名匹配：检查是否以黑名单域名结尾
        if domain.ends_with(&format!(".{}", blocked)) {
            return true;
        }
        false
    })
}

// 全局统计计数器
static REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);
static CACHE_HITS: AtomicUsize = AtomicUsize::new(0);
static CACHE_MISSES: AtomicUsize = AtomicUsize::new(0);

#[derive(Serialize)]
struct ServerStatus {
    total_requests: usize,
    cache_size: usize,
    cache_hits: usize,
    cache_misses: usize,
    cache_hit_rate: f64,
    upstream_servers: Vec<ServerInfo>,
    recent_queries: Vec<QueryInfo>,
}

#[derive(Serialize)]
struct ServerInfo {
    ip: String,
    weight: f64,
    avg_response_time: f64,
    success_count: usize,
    fail_count: usize,
    success_rate: f64,
}

#[derive(Serialize, Clone)]
struct QueryInfo {
    timestamp: String,
    domain: String,
    response_time: f64,
    cached: bool,
}

struct IpInfo {
    addr: std::net::SocketAddr,
    weight: f64,
    recent_times: VecDeque<f64>,
    success_count: AtomicUsize,
    fail_count: AtomicUsize,
}

// 最近查询记录（保存最近100条）
struct RecentQueries {
    queries: Mutex<VecDeque<QueryInfo>>,
}

impl RecentQueries {
    fn new() -> Self {
        Self {
            queries: Mutex::new(VecDeque::with_capacity(100)),
        }
    }

    async fn add(&self, query: QueryInfo) {
        let mut queries = self.queries.lock().await;
        if queries.len() >= 100 {
            queries.pop_front();
        }
        queries.push_back(query);
    }

    async fn get_recent(&self) -> Vec<QueryInfo> {
        let queries = self.queries.lock().await;
        queries.iter().cloned().collect()
    }
}

// 权重相关常量
const MAX_RECENT_TIMES: usize = 10;  // 最多保存10个最近查询时间
const RESPONSE_TIMEOUT_MS: f64 = 1000.0; // 响应超时时间
const WEIGHT_BOOST_FACTOR: f64 = 0.2; // 权重提升因子
const WEIGHT_DECAY_FACTOR: f64 = 0.9; // 权重衰减因子
const MIN_WEIGHT: f64 = 0.0001; // 最小权重
const MAX_WEIGHT: f64 = 1.0; // 最大权重

// 缓存相关常量
const DEFAULT_TTL: u64 = 43200;         // 默认缓存12小时
const MIN_TTL: u64 = 21600;             // 最小缓存6小时
const MAX_TTL: u64 = 86400 * 2;         // 最大缓存2天
const DNS_REFRESH_INTERVAL: u64 = 86400 * 1;    // DNS刷新间隔为1天
const WEIGHT_UPDATE_INTERVAL_SEC: u64 = 3600;   //权重计时器
const HEDGE_DELAY_MS: u64 = 1500;               // 触发第二路请求的延迟（毫秒）

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 从 1.1.1.1:53 解析 doh.18bit.cn 的IP地址列表
    let ips = resolve_ips().await?;
    if ips.is_empty() {
        return Err("No IPs resolved for doh.18bit.cn".into());
    }
    
    println!("Starting status server on http://localhost:18080");

    // 为每个解析到的IP创建客户端
    let mut clients = HashMap::new();
    let mut ip_infos = Vec::new();
    for ip in &ips {
        let client = Client::builder()
            .resolve("doh.18bit.cn", *ip)
            .build()?;
        clients.insert(*ip, client);
        ip_infos.push(IpInfo {
            addr: *ip,
            weight: 1.0,
            recent_times: VecDeque::new(),
            success_count: AtomicUsize::new(0),
            fail_count: AtomicUsize::new(0),
        });
    }

    // 使用 Arc<Mutex> 包装以便在任务间共享
    let clients = Arc::new(Mutex::new(clients));
    let ip_infos = Arc::new(Mutex::new(ip_infos));
    let cache = Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(10000).unwrap())));// 增加缓存容量到10000条
    let recent_queries = Arc::new(RecentQueries::new());

    // 克隆用于定时器
    let ip_infos_timer1 = ip_infos.clone();
    let ip_infos_timer2 = ip_infos.clone();
    let clients_timer = clients.clone();

    // 启动权重重新计算定时器
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(WEIGHT_UPDATE_INTERVAL_SEC));
        loop {
            interval.tick().await;
            recalculate_weights(&ip_infos_timer1).await;
        }
    });

    // 启动IP刷新定时器（每3天执行一次）
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(DNS_REFRESH_INTERVAL));
        loop {
            interval.tick().await;
            if let Err(e) = refresh_ips(&clients_timer, &ip_infos_timer2).await {
                eprintln!("Error refreshing IPs: {}", e);
            }
        }
    });

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:53").await?);
    let (response_tx, mut response_rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>(1000);

    // Spawn response sender
    let socket_clone = socket.clone();
    tokio::spawn(async move {
        while let Some((response, addr)) = response_rx.recv().await {
            if let Err(e) = socket_clone.send_to(&response, addr).await {
                eprintln!("Error sending response: {}", e);
            }
        }
    });
    
    // 启动状态监控Web服务器
    let app = Router::new()
        .route("/", get(get_status))
        .with_state((ip_infos.clone(), cache.clone(), recent_queries.clone()));
    
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:18080").await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    // 克隆 recent_queries 用于主循环
    let recent_queries_main = recent_queries.clone();
    
    loop {
        let mut buf = [0; 512];
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let query = buf[..len].to_vec();

        // 创建一个新任务来处理这个查询请求
        let clients_clone = clients.clone();
        let ip_infos_clone = ip_infos.clone();
        let cache_clone = cache.clone();
        let response_tx_clone = response_tx.clone();
        let recent_queries_clone = recent_queries_main.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_query(query, addr, clients_clone, ip_infos_clone, cache_clone, response_tx_clone, recent_queries_clone).await {
                eprintln!("Error handling query: {}", e);
            }
        });
    }
}

async fn handle_query(
    query: Vec<u8>,
    addr: std::net::SocketAddr,
    clients: Arc<Mutex<HashMap<std::net::SocketAddr, Client>>>,
    ip_infos: Arc<Mutex<Vec<IpInfo>>>,
    cache: Arc<Mutex<LruCache<Vec<u8>, (Vec<u8>, std::time::Instant)>>>,
    response_tx: mpsc::Sender<(Vec<u8>, std::net::SocketAddr)>,
    recent_queries: Arc<RecentQueries>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 使用规范化的缓存键，避免不同浏览器/实现导致的字节级差异引起的 cache miss
    let cache_key = build_cache_key(&query);

    // 从查询中解析域名
    let (domain, qtype) = extract_domain_from_query(&query);

    // 检查是否在黑名单中
    if is_domain_blocked(&domain) {
        // 构造NXDOMAIN响应
        let mut response = Vec::with_capacity(query.len());
        response.extend_from_slice(&query[0..2]); // 复制原查询ID
        response.extend_from_slice(&[0x84, 0x03]); // 设置响应标志：QR=1, RCODE=NXDOMAIN(3)
        response.extend_from_slice(&query[4..6]); // QDCOUNT
        response.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
        response.extend_from_slice(&query[12..]); // 复制查询部分

        // 记录被阻止的查询
        println!("{}: {} - {} - BLOCKED (blacklisted)", Local::now().format("%Y-%m-%d %H:%M:%S %z"), addr.ip(), domain);

        response_tx.send((response, addr)).await?;
        return Ok(());
    }

    // 为日志记录使用可读的查询类型
    let _qtype_str = match qtype {
        QueryType::A => "A",
        QueryType::AAAA => "AAAA",
        QueryType::MX => "MX",
        QueryType::CNAME => "CNAME",
        QueryType::TXT => "TXT",
        QueryType::NS => "NS",
        QueryType::SOA => "SOA",
        QueryType::PTR => "PTR",
        QueryType::SRV => "SRV",
        _ => "OTHER",
    };

    // 检查缓存
    {
        let mut cache_guard = cache.lock().await;
        match cache_guard.get(&cache_key) {
            Some((resp, expiry)) if expiry > &std::time::Instant::now() => {
                CACHE_HITS.fetch_add(1, Ordering::Relaxed);
                recent_queries.add(QueryInfo {
                    timestamp: Local::now().format("%H:%M:%S").to_string(),
                    domain: domain.clone(),
                    response_time: 0.0,
                    cached: true,
                }).await;
                
                let mut resp = resp.clone();
                resp[0..2].copy_from_slice(&query[0..2]); // 设置响应ID与查询ID匹配
                
                // 添加缓存命中日志
                println!("{}: {} - {} - HIT (cached)", Local::now().format("%Y-%m-%d %H:%M:%S %z"), addr.ip(), domain);
                
                response_tx.send((resp, addr)).await?;
                return Ok(());
            },
            _ => {
                // 缓存未命中，继续发起网络请求
                CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // Hedged requests: 先向一个IP发起请求，若超过阈值仍未返回，则对另一IP并发发起第二路请求
    // 先选择两个不同的上游IP
    let (first_index, second_index, first_addr, second_addr, first_client, second_client) = {
        let ip_infos_guard = ip_infos.lock().await;
        let first_index = choose_ip_index(&ip_infos_guard);
        let second_index = (first_index + 1) % ip_infos_guard.len();
        let first_addr = ip_infos_guard[first_index].addr;
        let second_addr = ip_infos_guard[second_index].addr;
        let clients_guard = clients.lock().await;
        let first_client = clients_guard.get(&first_addr).unwrap().clone();
        let second_client = clients_guard.get(&second_addr).unwrap().clone();
        (first_index, second_index, first_addr, second_addr, first_client, second_client)
    };

    // 启动两路请求（第二路有延迟）
    let q1 = query.clone();
    let handle1 = tokio::spawn(async move {
        let start = std::time::Instant::now();
        let res = first_client
            .post("https://doh.18bit.cn/dns-query")
            .header("Content-Type", "application/dns-message")
            .body(q1)
            .send()
            .await;
        let bytes_opt = match res {
            Ok(resp) => resp.bytes().await.ok(),
            Err(_) => None,
        };
        if let Some(bytes) = bytes_opt {
            Some((bytes.to_vec(), start.elapsed(), first_index, first_addr))
        } else {
            None
        }
    });

    let q2 = query.clone();
    let handle2 = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(HEDGE_DELAY_MS)).await;
        let start = std::time::Instant::now();
        let res = second_client
            .post("https://doh.18bit.cn/dns-query")
            .header("Content-Type", "application/dns-message")
            .body(q2)
            .send()
            .await;
        let bytes_opt = match res {
            Ok(resp) => resp.bytes().await.ok(),
            Err(_) => None,
        };
        if let Some(bytes) = bytes_opt {
            Some((bytes.to_vec(), start.elapsed(), second_index, second_addr))
        } else {
            None
        }
    });

    let mut picked: Option<(Vec<u8>, std::time::Duration, usize, std::net::SocketAddr)> = None;
    tokio::select! {
        res1 = handle1 => {
            if let Ok(Some(r)) = res1 { picked = Some(r); }
        },
        res2 = handle2 => {
            if let Ok(Some(r)) = res2 { picked = Some(r); }
        },
    }

    if let Some((data, duration, final_chosen_index, chosen_addr)) = picked {
        let duration_ms = duration.as_millis() as f64;
        {
            let mut ip_infos_guard = ip_infos.lock().await;
            update_weight(&mut ip_infos_guard[final_chosen_index], duration_ms, true);
            ip_infos_guard[final_chosen_index].success_count.fetch_add(1, Ordering::Relaxed);
        }
        
        // 记录查询信息
        recent_queries.add(QueryInfo {
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            domain: domain.clone(),
            response_time: duration_ms,
            cached: false,
        }).await;
        println!("{}: {} - {} - {:.2}ms", Local::now().format("%Y-%m-%d %H:%M:%S %z"), chosen_addr.ip(), domain, duration_ms);

        // 增加请求计数并检查是否需要打印权重信息
        // 使用取模运算保持计数器在合理范围内（1000000表示100万）
        let count = (REQUEST_COUNT.fetch_add(1, Ordering::Relaxed) % 1000000) + 1;
        
        // 每100个请求打印一次统计信息
        if count % 100 == 0 {
            let total_count = REQUEST_COUNT.load(Ordering::Relaxed);
            println!("{}: Processed {} requests (total: {}), current IP weights:", 
                Local::now().format("%Y-%m-%d %H:%M:%S %z"), 
                count,
                total_count
            );
            {
                let ip_infos_guard = ip_infos.lock().await;
                for info in ip_infos_guard.iter() {
                    println!("  {}: weight={:.4}", info.addr.ip(), info.weight);
                }
            }
        }

        let resp_vec = data;

        // 从DNS响应中提取TTL并进行缓存
        let ttl = if let Ok(packet) = Packet::parse(&resp_vec) {
            // 获取所有记录中的最小TTL值
            packet.answers.iter()
                .chain(packet.additional.iter())
                .chain(packet.nameservers.iter())
                .filter_map(|record| Some(record.ttl))
                .min()
                .unwrap_or(DEFAULT_TTL as u32) as u64
        } else {
            DEFAULT_TTL
        };

        // 确保TTL在合理范围内
        let ttl = ttl.clamp(MIN_TTL, MAX_TTL);

        // 设置缓存
        {
            let mut cache_guard = cache.lock().await;
            cache_guard.put(
                cache_key, 
                (resp_vec.clone(), std::time::Instant::now() + std::time::Duration::from_secs(ttl))
            );
            
            // 打印缓存信息
            println!("{}: Cached {} for {}h{}m", 
                Local::now().format("%Y-%m-%d %H:%M:%S %z"),
                domain,
                ttl / 3600,
                (ttl % 3600) / 60
            );
        }

        // 发送响应回客户端
        response_tx.send((resp_vec, addr)).await?;
    } else {
        // 两路都失败：对首选IP记一次失败并按超时处理
        let mut ip_infos_guard = ip_infos.lock().await;
        update_weight(&mut ip_infos_guard[first_index], RESPONSE_TIMEOUT_MS, false);
        ip_infos_guard[first_index].fail_count.fetch_add(1, Ordering::Relaxed);
    }

    Ok(())
}

async fn recalculate_weights(ip_infos: &Arc<Mutex<Vec<IpInfo>>>) {
    let mut ip_infos_guard = ip_infos.lock().await;
    for info in ip_infos_guard.iter_mut() {
        if !info.recent_times.is_empty() {
            // 使用最近的响应时间计算新权重
            let avg_time: f64 = info.recent_times.iter().sum::<f64>() / info.recent_times.len() as f64;
            if avg_time < RESPONSE_TIMEOUT_MS {
                // 使用平均响应时间计算新权重
                let new_weight = ((RESPONSE_TIMEOUT_MS - avg_time) / RESPONSE_TIMEOUT_MS)
                    .max(MIN_WEIGHT)
                    .min(MAX_WEIGHT);
                // 平滑过渡到新权重
                info.weight = (info.weight * 0.3 + new_weight * 0.7).max(MIN_WEIGHT).min(MAX_WEIGHT);
            } else {
                // 如果平均响应时间超过超时时间，降低权重
                info.weight = (info.weight * WEIGHT_DECAY_FACTOR).max(MIN_WEIGHT);
            }
        }
        // 保留历史记录，但限制数量
        while info.recent_times.len() > MAX_RECENT_TIMES {
            info.recent_times.pop_front();
        }
    }
    
    // 打印当前所有IP的权重情况
    println!("{}: Weights recalculated", Local::now().format("%Y-%m-%d %H:%M:%S %z"));
    for info in ip_infos_guard.iter() {
        let avg_time = if !info.recent_times.is_empty() {
            info.recent_times.iter().sum::<f64>() / info.recent_times.len() as f64
        } else {
            0.0
        };
        println!("  {}: weight={:.4}, avg_time={:.2}ms", info.addr.ip(), info.weight, avg_time);
    }
}

async fn refresh_ips(
    clients: &Arc<Mutex<HashMap<std::net::SocketAddr, Client>>>,
    ip_infos: &Arc<Mutex<Vec<IpInfo>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}: Refreshing IPs for doh.18bit.cn", Local::now().format("%Y-%m-%d %H:%M:%S %z"));
    let new_ips = resolve_ips().await?;
    if new_ips.is_empty() {
        return Err("No new IPs resolved".into());
    }

    let mut clients_guard = clients.lock().await;
    let mut ip_infos_guard = ip_infos.lock().await;

    // 清除旧IP
    clients_guard.clear();
    ip_infos_guard.clear();

    // 添加新IP
    for ip in &new_ips {
        let client = Client::builder()
            .resolve("doh.18bit.cn", *ip)
            .build()?;
        clients_guard.insert(*ip, client);
        ip_infos_guard.push(IpInfo {
            addr: *ip,
            weight: 1.0,
            recent_times: VecDeque::new(),
            success_count: AtomicUsize::new(0),
            fail_count: AtomicUsize::new(0),
        });
    }

    println!("{}: Refreshed {} IPs", Local::now().format("%Y-%m-%d %H:%M:%S %z"), new_ips.len());
    Ok(())
}

fn choose_ip_index(ip_infos: &Vec<IpInfo>) -> usize {
    if ip_infos.is_empty() {
        panic!("no available ip address");
    }
    let total_weight: f64 = ip_infos.iter().map(|i| i.weight).sum();
    if total_weight == 0.0 {
        return fastrand::usize(0..ip_infos.len());
    }
    let mut rand_val = fastrand::f64() * total_weight;
    for (_index, info) in ip_infos.iter().enumerate() {
        rand_val -= info.weight;
        if rand_val <= 0.0 {
            return _index;  // ✅ 返回选中的IP索引
        }
    }
    0 // fallback
}

fn update_weight(info: &mut IpInfo, duration_ms: f64, is_success: bool) {
    // 记录响应时间，包括失败的请求（用超时时间记录）
    info.recent_times.push_back(if is_success { duration_ms } else { RESPONSE_TIMEOUT_MS });
    
    // 维护最近响应时间队列
    while info.recent_times.len() > MAX_RECENT_TIMES {
        info.recent_times.pop_front();
    }

    // 计算最近请求的平均响应时间
    let avg_time = info.recent_times.iter().sum::<f64>() / info.recent_times.len() as f64;
    
    if is_success {
        if duration_ms < RESPONSE_TIMEOUT_MS {
            // 使用更精细的响应质量计算
            let response_quality = ((RESPONSE_TIMEOUT_MS - avg_time) / RESPONSE_TIMEOUT_MS).max(0.0);
            let dynamic_boost = (WEIGHT_BOOST_FACTOR * 0.05) * response_quality * response_quality;
            
            // 平滑权重调整
            let new_weight = (info.weight + dynamic_boost).min(MAX_WEIGHT);
            // 使用指数移动平均，保持权重变化平滑
            info.weight = info.weight * 0.8 + new_weight * 0.2;
        } else {
            // 响应超时但成功，轻微降低权重
            let decay = 0.98; // 更温和的衰减
            info.weight = (info.weight * decay).max(MIN_WEIGHT);
        }
    } else {
        // 请求失败时的权重调整
        let severity = (duration_ms / RESPONSE_TIMEOUT_MS).min(2.0); // 限制惩罚程度
        let decay = WEIGHT_DECAY_FACTOR.powf(severity); // 根据超时程度调整衰减
        
        // 确保新权重不会小于最小值
        let new_weight = (info.weight * decay).max(MIN_WEIGHT);
        // 平滑过渡到新权重
        info.weight = (info.weight * 0.7 + new_weight * 0.3).max(MIN_WEIGHT);
    }

    // 确保最终权重在合法范围内，并保持4位小数精度
    info.weight = (info.weight * 10000.0).round() / 10000.0;
    info.weight = info.weight.max(MIN_WEIGHT).min(MAX_WEIGHT);
}

fn extract_domain_from_query(query: &[u8]) -> (String, QueryType) {
    let mut domain = "unknown".to_string();
    let mut qtype = QueryType::A;  // 默认类型

    if query.len() >= 13 {
        let mut offset = 12; // Skip header
        let mut labels = Vec::new();
        
        // 解析域名部分
        loop {
            if offset >= query.len() {
                break;
            }
            let len = query[offset] as usize;
            if len == 0 {
                break;
            }
            if len & 0xC0 == 0xC0 {
                // 压缩指针：获取指针值并跳转到目标位置
                let pointer = ((len & 0x3F) as u16) << 8 | query[offset + 1] as u16;
                offset = pointer as usize;
                continue; // 继续解析，不退出
            }
            offset += 1;
            if offset + len > query.len() {
                break;
            }
            let label = &query[offset..offset + len];
            labels.push(String::from_utf8_lossy(label).to_string());
            offset += len;
        }
        
        if !labels.is_empty() {
            domain = labels.join(".");
            
            // 解析查询类型
            if offset + 4 <= query.len() {
                offset += 1; // 跳过结束的零字节
                qtype = match u16::from_be_bytes([query[offset], query[offset + 1]]) {
                    1 => QueryType::A,
                    2 => QueryType::NS,
                    5 => QueryType::CNAME,
                    6 => QueryType::SOA,
                    12 => QueryType::PTR,
                    15 => QueryType::MX,
                    16 => QueryType::TXT,
                    28 => QueryType::AAAA,
                    33 => QueryType::SRV,
                    _ => QueryType::A,
                };
            }
        }
    }

    (domain, qtype)
}

// 将查询规范化为缓存键：lowercase 的域名 + 无尾点 + qtype + qclass
// 这样可以屏蔽不同客户端在 Header 标志位、EDNS/OPT、padding、大小写等上的差异，但保留真正影响响应的因素
fn build_cache_key(query: &[u8]) -> Vec<u8> {
    // 方法1: 尝试完整解析DNS报文
    if let Ok(packet) = Packet::parse(query) {
        if let Some(q) = packet.questions.get(0) {
            let mut name = q.qname.to_string();
            // 去掉尾部的点并统一小写
            if name.ends_with('.') { name.pop(); }
            let name = name.trim_end_matches('.').to_ascii_lowercase();

            // 获取查询类型的数字值
            let qtype_num: u16 = match q.qtype {
                QueryType::A => 1,
                QueryType::NS => 2,
                QueryType::CNAME => 5,
                QueryType::SOA => 6,
                QueryType::PTR => 12,
                QueryType::MX => 15,
                QueryType::TXT => 16,
                QueryType::AAAA => 28,
                QueryType::SRV => 33,
                // 对于其他类型，直接使用其数字值（包括HTTPS、SVCB等新类型）
                _ => 255, // 统一处理未知类型
            };

            let qclass_num: u16 = match q.qclass {
                dns_parser::QueryClass::IN => 1,
                dns_parser::QueryClass::CH => 3,
                dns_parser::QueryClass::HS => 4,
                dns_parser::QueryClass::Any => 255,
                _ => 1,
            };

            // 构造稳定 key：name|qtype|qclass
            let key_str = format!("{}|{}|{}", name, qtype_num, qclass_num);
            // 临时调试：打印缓存键（仅在缓存未命中时，用于诊断）
            if CACHE_MISSES.load(Ordering::Relaxed) % 10 == 0 {
                eprintln!("DEBUG: Cache key generated for {}: {}", name, key_str);
            }
            return key_str.into_bytes();
        }
    }

    // 方法2: 如果完整解析失败，尝试手动解析（处理压缩指针等情况）
    if query.len() >= 13 {
        let mut offset = 12; // Skip header
        let mut labels = Vec::new();

        // 手动解析域名（处理压缩指针）
        loop {
            if offset >= query.len() {
                break;
            }
            let len = query[offset] as usize;
            if len == 0 {
                break;
            }
            if len & 0xC0 == 0xC0 {
                // 压缩指针：获取指针值并跳转到目标位置
                let pointer = ((len & 0x3F) as u16) << 8 | query[offset + 1] as u16;
                offset = pointer as usize;
                continue; // 继续解析，不退出
            }
            offset += 1;
            if offset + len > query.len() {
                break;
            }
            let label = &query[offset..offset + len];
            if let Ok(label_str) = std::str::from_utf8(label) {
                labels.push(label_str.to_ascii_lowercase());
            }
            offset += len;
        }

        if !labels.is_empty() {
            let domain = labels.join(".");
            // 解析查询类型
            if offset + 4 <= query.len() {
                offset += 1; // 跳过结束的零字节
                let qtype_num = u16::from_be_bytes([query[offset], query[offset + 1]]);
                let qclass_num = u16::from_be_bytes([query[offset + 2], query[offset + 3]]);

                // 构造缓存键
                let key_str = format!("{}|{}|{}", domain, qtype_num, qclass_num);
                return key_str.into_bytes();
            }
        }
    }

    // 方法3: 最后的回退方案 - 使用原始查询（仅清零ID）
    let mut fallback = query.to_vec();
    if fallback.len() >= 2 {
        fallback[0..2].fill(0);
    }
    fallback
}


async fn get_status(
    State((ip_infos, cache, recent_queries)): State<(
        Arc<Mutex<Vec<IpInfo>>>,
        Arc<Mutex<LruCache<Vec<u8>, (Vec<u8>, std::time::Instant)>>>,
        Arc<RecentQueries>
    )>,
) -> Html<String> {
    let ip_infos_guard = ip_infos.lock().await;
    let cache_guard = cache.lock().await;
    let recent = recent_queries.get_recent().await;
    
    let cache_hits = CACHE_HITS.load(Ordering::Relaxed);
    let cache_misses = CACHE_MISSES.load(Ordering::Relaxed);
    let total_requests = cache_hits + cache_misses;
    let hit_rate = if total_requests > 0 {
        (cache_hits as f64 / total_requests as f64) * 100.0
    } else {
        0.0
    };

    let status = ServerStatus {
        total_requests: REQUEST_COUNT.load(Ordering::Relaxed),
        cache_size: cache_guard.len(),
        cache_hits,
        cache_misses,
        cache_hit_rate: hit_rate,
        upstream_servers: ip_infos_guard
            .iter()
            .map(|info| {
                let success = info.success_count.load(Ordering::Relaxed);
                let fail = info.fail_count.load(Ordering::Relaxed);
                let total = success + fail;
                let success_rate = if total > 0 {
                    (success as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                
                ServerInfo {
                    ip: info.addr.ip().to_string(),
                    weight: info.weight,
                    avg_response_time: if !info.recent_times.is_empty() {
                        info.recent_times.iter().sum::<f64>() / info.recent_times.len() as f64
                    } else {
                        0.0
                    },
                    success_count: success,
                    fail_count: fail,
                    success_rate,
                }
            })
            .collect(),
        recent_queries: recent,
    };

    let server_items = status.upstream_servers
        .iter()
        .map(|server| format!(
            r#"<div class="card server-item">
                <div class="status-item">
                    <span>服务器IP</span>
                    <span>{}</span>
                </div>
                <div class="status-item">
                    <span>权重</span>
                    <span>{:.4}</span>
                </div>
                <div class="status-item">
                    <span>平均响应时间</span>
                    <span>{:.2}ms</span>
                </div>
                <div class="status-item">
                    <span>成功率</span>
                    <span class="success-rate">{:.1}%</span>
                </div>
                <div class="status-item">
                    <span>成功/失败</span>
                    <span>{}/{}</span>
                </div>
            </div>"#,
            server.ip, server.weight, server.avg_response_time,
            server.success_rate, server.success_count, server.fail_count
        ))
        .collect::<Vec<_>>()
        .join("\n");

    let query_items = status.recent_queries
        .iter()
        .map(|query| format!(
            r#"<div class="query-item">
                <span>{}</span>
                <span>{}</span>
                <span>{:.2}ms</span>
                <span>{}</span>
            </div>"#,
            query.timestamp,
            query.domain,
            query.response_time,
            if query.cached { "HIT" } else { "MISS" }
        ))
        .collect::<Vec<_>>()
        .join("\n");

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>18bit DNS代理服务器状态</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="5">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 15px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .card {{ 
            background: #fff;
            border-radius: 6px;
            padding: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .status-item {{ 
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid #eee;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }}
        .server-list {{ 
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
        }}
        .server-item {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin: 0;
        }}
        .queries-list {{
            margin-top: 12px;
            max-height: 300px;
            overflow-y: auto;
        }}
        .query-item {{
            display: grid;
            grid-template-columns: 80px 2fr 80px 60px;
            gap: 10px;
            padding: 8px;
            border-bottom: 1px solid #eee;
        }}
        .query-item.header {{
            font-weight: bold;
            background: #f8f9fa;
            position: sticky;
            top: 0;
        }}
        .success-rate {{
            color: #28a745;
            font-weight: bold;
        }}
        .cache-stats {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-top: 12px;
        }}
        @media (max-width: 768px) {{
            .server-list, .cache-stats {{
                grid-template-columns: 1fr;
            }}
            .query-item {{
                font-size: 14px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>18bit DNS代理服务器状态</h1>
        <div class="cache-stats">

            <div class="card">
            <div class="status-item">
                <span>DoH总请求数</span>
                <span>{}</span>
            </div>
            <div class="status-item">
                <span>缓存条目数</span>
                <span>{}</span>
            </div>
            <div class="status-item">
                <span>缓存命中率</span>
                <span class="success-rate">{:.1}%</span>
            </div>
        </div>

            <div class="card">
            <div class="status-item">
                <span>缓存统计</span>
            </div>
                <div class="status-item">
                    <span>命中次数</span>
                    <span>{}</span>
                </div>
                <div class="status-item">
                    <span>未命中次数</span>
                    <span>{}</span>
                </div>
            </div>
        </div>
        
        <h2>18bit 节点状态</h2>
        <div class="server-list">
            {}
        </div>

        <h2>最近查询记录</h2>
        <div class="card queries-list">
            <div class="query-item header">
                <span>时间</span>
                <span>域名</span>
                <span>响应时间</span>
                <span>缓存</span>
            </div>
            {}
        </div>
    </div>
    <script>
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>"#,
        status.total_requests,
        status.cache_size,
        status.cache_hit_rate,
        status.cache_hits,
        status.cache_misses,
        server_items,
        query_items
    );

    Html(html)
}

async fn resolve_ips() -> Result<Vec<std::net::SocketAddr>, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("1.1.1.1:53").await?;

    // Build DNS query for doh.18bit.cn A
    // 构建 DNS 查询
    let mut builder = Builder::new_query(12345, true);
    builder.add_question("doh.18bit.cn", false, dns_parser::QueryType::A, dns_parser::QueryClass::IN);
    let query = builder.build().map_err(|_| "Failed to build DNS query")?;

    socket.send(&query).await?;
    let mut buf = [0; 512];
    let len = socket.recv(&mut buf).await?;
    let response_data = &buf[..len];

    let packet = Packet::parse(response_data)?;
    let mut ips = Vec::new();
    for answer in packet.answers {
        if let dns_parser::RData::A(addr) = answer.data {
            ips.push(std::net::SocketAddr::new(std::net::IpAddr::V4(addr.0), 443));
        }
    }
    Ok(ips)
}
