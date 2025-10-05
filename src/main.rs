use tokio::net::UdpSocket;
use reqwest::Client;
use lru::LruCache;
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use dns_parser::{Builder, Packet};
use chrono::Local;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{interval, Duration};
use std::sync::atomic::{AtomicUsize, Ordering};

static REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

struct IpInfo {
    addr: std::net::SocketAddr,
    weight: f64,
    recent_times: VecDeque<f64>,
}

const MAX_RECENT_TIMES: usize = 10;
const RESPONSE_TIMEOUT_MS: f64 = 1000.0;
const WEIGHT_BOOST_FACTOR: f64 = 0.2;
const WEIGHT_DECAY_FACTOR: f64 = 0.9; // 提高衰减因子，使权重降低更平缓
const MIN_WEIGHT: f64 = 0.0001; // 设置最小权重为0.0001，确保永远不会为0或负数
const MAX_WEIGHT: f64 = 1.0;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 从 1.1.1.1:53 解析 doh.18bit.cn 的IP地址列表
    let ips = resolve_ips().await?;
    if ips.is_empty() {
        return Err("No IPs resolved for doh.18bit.cn".into());
    }

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
        });
    }

    // 使用 Arc<Mutex> 包装以便在任务间共享
    let clients = Arc::new(Mutex::new(clients));
    let ip_infos = Arc::new(Mutex::new(ip_infos));
    let cache = Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(10000).unwrap())));// 增加缓存容量到10000条

    // 克隆用于定时器
    let ip_infos_timer1 = ip_infos.clone();
    let ip_infos_timer2 = ip_infos.clone();
    let clients_timer = clients.clone();

    // 启动权重重新计算定时器（每60分钟执行一次）
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(3600)); // 60分钟
        loop {
            interval.tick().await;
            recalculate_weights(&ip_infos_timer1).await;
        }
    });

    // 启动IP刷新定时器（每24小时执行一次）
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(86400)); // 24 hours
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

    loop {
        let mut buf = [0; 512];
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let query = buf[..len].to_vec();

        // 创建一个新任务来处理这个查询请求
        let clients_clone = clients.clone();
        let ip_infos_clone = ip_infos.clone();
        let cache_clone = cache.clone();
        let response_tx_clone = response_tx.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_query(query, addr, clients_clone, ip_infos_clone, cache_clone, response_tx_clone).await {
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
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cache_key = query.clone();
    cache_key[0..2].fill(0); // Zero out the query ID for caching purposes

    // 从查询中解析域名
    let domain = extract_domain_from_query(&query);

    // 检查缓存
    {
        let mut cache_guard = cache.lock().await;
        if let Some((resp, expiry)) = cache_guard.get(&cache_key) {
            if expiry > &std::time::Instant::now() {
                let mut resp = resp.clone();
                resp[0..2].copy_from_slice(&query[0..2]); // 设置响应ID与查询ID匹配
                response_tx.send((resp, addr)).await?;
                return Ok(());
            }
        }
    }

    // Weighted random selection and retry logic
    let mut chosen_index;
    {
        let ip_infos_guard = ip_infos.lock().await;
        chosen_index = choose_ip_index(&ip_infos_guard);
    }

    let mut attempts = 0;
    let max_attempts = 3; // 最大重试次数
    let mut response = None;
    let mut total_duration = std::time::Duration::default();
    let mut final_chosen_index = chosen_index;
    let mut chosen_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));

    while attempts < max_attempts {
        let client;
        {
            let ip_infos_guard = ip_infos.lock().await;
            chosen_addr = ip_infos_guard[chosen_index].addr;
            let clients_guard = clients.lock().await;
            client = clients_guard.get(&chosen_addr).unwrap().clone();
        }

        let start = std::time::Instant::now();
        let res = client
            .post("https://doh.18bit.cn/dns-query")
            .header("Content-Type", "application/dns-message")
            .body(query.clone())
            .send()
            .await;
        let duration = start.elapsed();
        total_duration += duration;

        if let Ok(resp) = res {
            if let Ok(data) = resp.bytes().await {
                response = Some(data);
                final_chosen_index = chosen_index;
                break;
            }
        }

        attempts += 1;
        if attempts < max_attempts {
            // Retry same IP
        } else {
            // 切换到下一个IP
            {
                let ip_infos_guard = ip_infos.lock().await;
                chosen_index = (chosen_index + 1) % ip_infos_guard.len();
            }
        }
    }

    if let Some(data) = response {
        let duration_ms = total_duration.as_millis() as f64;
        {
            let mut ip_infos_guard = ip_infos.lock().await;
            update_weight(&mut ip_infos_guard[final_chosen_index], duration_ms, true);
        }
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

        let resp_vec = data.to_vec();

        // 缓存响应，TTL为3600秒
        {
            let mut cache_guard = cache.lock().await;
            cache_guard.put(cache_key, (resp_vec.clone(), std::time::Instant::now() + std::time::Duration::from_secs(3600)));
        }

        // 发送响应回客户端
        response_tx.send((resp_vec, addr)).await?;
    } else {
        //所有尝试失败，更新最后尝试的IP的权重
        {
            let mut ip_infos_guard = ip_infos.lock().await;
            update_weight(&mut ip_infos_guard[chosen_index], total_duration.as_millis() as f64, false);
        }
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

fn extract_domain_from_query(query: &[u8]) -> String {
    if query.len() < 13 {
        return "unknown".to_string();
    }
    let mut offset = 12; // Skip header
    let mut labels = Vec::new();
    loop {
        if offset >= query.len() {
            break;
        }
        let len = query[offset] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer, for simplicity, return unknown
            return "unknown".to_string();
        }
        offset += 1;
        if offset + len > query.len() {
            break;
        }
        let label = &query[offset..offset + len];
        labels.push(String::from_utf8_lossy(label).to_string());
        offset += len;
    }
    labels.join(".")
}


async fn resolve_ips() -> Result<Vec<std::net::SocketAddr>, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("1.1.1.1:53").await?;

    // Build DNS query for doh.18bit.cn A
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
