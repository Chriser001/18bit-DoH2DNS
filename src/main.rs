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
use fastrand;

struct IpInfo {
    addr: std::net::SocketAddr,
    weight: f64,
    recent_times: VecDeque<f64>,
}

const MAX_RECENT_TIMES: usize = 10;
const RESPONSE_TIMEOUT_MS: f64 = 1000.0;
const WEIGHT_BOOST_FACTOR: f64 = 0.2;
const WEIGHT_DECAY_FACTOR: f64 = 0.7;
const MIN_WEIGHT: f64 = 0.3;
const MAX_WEIGHT: f64 = 1.0;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolve IPs for doh.18bit.cn from 1.1.1.1:53
    let ips = resolve_ips().await?;
    if ips.is_empty() {
        return Err("No IPs resolved for doh.18bit.cn".into());
    }

    // Create clients for each IP with resolve
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

    // Wrap in Arc<Mutex> for sharing between tasks
    let clients = Arc::new(Mutex::new(clients));
    let ip_infos = Arc::new(Mutex::new(ip_infos));
    let cache = Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(3000).unwrap())));

    // Clone for timers
    let ip_infos_timer1 = ip_infos.clone();
    let ip_infos_timer2 = ip_infos.clone();
    let clients_timer = clients.clone();

    // Start weight recalculation timer (every 5 minutes)
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            recalculate_weights(&ip_infos_timer1).await;
        }
    });

    // Start IP refresh timer (every 12 hours)
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(43200)); // 12 hours
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

        // Spawn a task to handle this query
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

    // Parse domain from query
    let domain = extract_domain_from_query(&query);

    // Check cache
    {
        let mut cache_guard = cache.lock().await;
        if let Some((resp, expiry)) = cache_guard.get(&cache_key) {
            if expiry > &std::time::Instant::now() {
                let mut resp = resp.clone();
                resp[0..2].copy_from_slice(&query[0..2]); // Set response ID to match query ID
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
    let max_attempts = 3;
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
            // Switch to next IP
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

        let resp_vec = data.to_vec();

        // Cache the response with TTL 3600 seconds
        {
            let mut cache_guard = cache.lock().await;
            cache_guard.put(cache_key, (resp_vec.clone(), std::time::Instant::now() + std::time::Duration::from_secs(3600)));
        }

        // Send response back to client
        response_tx.send((resp_vec, addr)).await?;
    } else {
        // All attempts failed, update weight for last tried IP
        {
            let mut ip_infos_guard = ip_infos.lock().await;
            update_weight(&mut ip_infos_guard[chosen_index], total_duration.as_millis() as f64, false);
        }
    }

    Ok(())
}

async fn recalculate_weights(ip_infos: &Arc<Mutex<Vec<IpInfo>>>) {
    let mut ip_infos_guard = ip_infos.lock().await;
    // Reset weights to 1.0 for all IPs
    for info in ip_infos_guard.iter_mut() {
        info.weight = 1.0;
        info.recent_times.clear();
    }
    println!("{}: Weights recalculated", Local::now().format("%Y-%m-%d %H:%M:%S %z"));
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

    // Clear old data
    clients_guard.clear();
    ip_infos_guard.clear();

    // Add new IPs
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
        panic!("No IPs available");
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
    if is_success && duration_ms < RESPONSE_TIMEOUT_MS {
        let boost = (RESPONSE_TIMEOUT_MS - duration_ms) / RESPONSE_TIMEOUT_MS * WEIGHT_BOOST_FACTOR;
        info.weight = (info.weight + boost).min(MAX_WEIGHT);
        info.recent_times.push_back(duration_ms);
        if info.recent_times.len() > MAX_RECENT_TIMES {
            info.recent_times.pop_front();
        }
    } else {
        info.weight = (info.weight * WEIGHT_DECAY_FACTOR).max(MIN_WEIGHT);
    }
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
