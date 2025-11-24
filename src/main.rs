use clap::Parser;
use colored::*;
use futures::stream::{self, StreamExt};
use ipnet::Ipv4Net;
use snmp2::{SyncSession, Value, Oid};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const PRINTER_PORT: u16 = 9100;
const OID_SYS_DESCR: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "192.168.199.0/24")]
    network: String,

    #[arg(short, long, default_value_t = 2000)]
    timeout_ms: u64,

    #[arg(short, long, default_value_t = 50)]
    concurrency: usize,
}

#[derive(Debug)]
struct PrinterInfo {
    ip: IpAddr,
    model: String,
    source: String,
}

async fn is_port_open(ip: IpAddr, port: u16, timeout_ms: u64) -> bool {
    let addr = SocketAddr::new(ip, port);
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

/// 1. PJL 探测 (HP, Brother 等)
async fn get_pjl_info(ip: IpAddr, timeout_ms: u64) -> Option<String> {
    let addr = SocketAddr::new(ip, PRINTER_PORT);
    let mut stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await.ok()?.ok()?;

    let pjl_cmd = b"\x1B%-12345X@PJL INFO ID\r\n\x1B%-12345X";
    if stream.write_all(pjl_cmd).await.is_err() { return None; }

    let mut buffer = [0; 1024];
    if let Ok(Ok(n)) = timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
        if n > 0 {
            let raw = String::from_utf8_lossy(&buffer[..n]);
            if raw.contains("ID") {
                let clean = raw.replace("ID=", "").replace("ID =", "").replace("\"", "").trim().to_string();
                let model_line = clean.lines().find(|l| !l.trim().is_empty()).unwrap_or("Unknown PJL").to_string();
                return Some(model_line);
            }
        }
    }
    None
}

/// 2. Zebra SGD 探测 (最稳的斑马识别法)
/// 发送: ! U1 getvar "device.product_name"
async fn get_zebra_sgd_info(ip: IpAddr, timeout_ms: u64) -> Option<String> {
    let addr = SocketAddr::new(ip, PRINTER_PORT);
    let mut stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await.ok()?.ok()?;

    // 注意: 命令必须以换行符结尾
    let sgd_cmd = b"! U1 getvar \"device.product_name\"\r\n";
    if stream.write_all(sgd_cmd).await.is_err() { return None; }

    let mut buffer = [0; 1024];
    // SGD 响应很快，通常就是一行纯文本，例如 "GX430t"
    if let Ok(Ok(n)) = timeout(Duration::from_millis(1500), stream.read(&mut buffer)).await {
        if n > 0 {
            let raw = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
            // 过滤掉空响应或乱码
            if !raw.is_empty() && raw.len() > 2 && raw.chars().all(|c| c.is_ascii() && !c.is_control()) {
                // 有时候会返回双引号，去掉它
                let clean = raw.replace("\"", "");
                return Some(format!("Zebra {}", clean));
            }
        }
    }
    None
}

/// 3. Zebra ZPL ~HI 探测 (老式备用)
async fn get_zpl_hi_info(ip: IpAddr, timeout_ms: u64) -> Option<String> {
    let addr = SocketAddr::new(ip, PRINTER_PORT);
    let mut stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await.ok()?.ok()?;

    let zpl_cmd = b"~HI";
    if stream.write_all(zpl_cmd).await.is_err() { return None; }

    let mut buffer = [0; 1024];
    if let Ok(Ok(n)) = timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
        if n > 0 {
            let raw = String::from_utf8_lossy(&buffer[..n]).to_string();
            if raw.contains(",") {
                // 尝试粗暴提取：取逗号分隔后的最长那一段，通常是型号
                let parts: Vec<&str> = raw.split(',').collect();
                if let Some(longest) = parts.iter().max_by_key(|p| p.len()) {
                    if longest.len() > 3 {
                        return Some(format!("Zebra ZPL ({})", longest.trim()));
                    }
                }
            }
        }
    }
    None
}

/// 4. SNMP 探测
async fn get_snmp_info(ip: IpAddr) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        let target = format!("{}:161", ip);
        let mut sess = SyncSession::new_v2c(target, b"public", Some(Duration::from_secs(1)), 0).ok()?;
        let oid = Oid::from(OID_SYS_DESCR).ok()?;

        if let Ok(response) = sess.get(&oid) {
            if let Some((_, Value::OctetString(bytes))) = response.varbinds.into_iter().next() {
                return Some(String::from_utf8_lossy(&bytes).trim().to_string());
            }
        }
        None
    }).await.ok().flatten()
}

/// 5. 兜底策略：如果上面都失败了，但端口能读出数据，就把数据打印出来
/// 很多老式打印机会在连接建立时发送 "Press Enter..." 或者型号 Banner
async fn get_raw_banner(ip: IpAddr, timeout_ms: u64) -> Option<String> {
    let addr = SocketAddr::new(ip, PRINTER_PORT);
    let mut stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await.ok()?.ok()?;

    // 此时不发任何指令，只是干等 500ms，看它会不会吐出 banner
    let mut buffer = [0; 1024];
    if let Ok(Ok(n)) = timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        if n > 0 {
            let raw = String::from_utf8_lossy(&buffer[..n]).replace(['\r', '\n'], " ").trim().to_string();
            if raw.len() > 3 && raw.chars().any(|c| c.is_alphabetic()) {
                return Some(raw);
            }
        }
    }
    None
}

async fn scan_target(ip: IpAddr, timeout_ms: u64) -> Option<PrinterInfo> {
    // 1. 严格过滤：必须 9100 通
    if !is_port_open(ip, PRINTER_PORT, timeout_ms).await {
        return None;
    }

    // 按顺序尝试各种协议
    // A. 尝试 Zebra SGD (文本指令 ! U1 getvar) -> 针对 GX430t 优化
    if let Some(model) = get_zebra_sgd_info(ip, timeout_ms).await {
        return Some(PrinterInfo { ip, model, source: "SGD (Zebra)".to_string() });
    }

    // B. 尝试 PJL (HP/通用)
    if let Some(model) = get_pjl_info(ip, timeout_ms).await {
        return Some(PrinterInfo { ip, model, source: "PJL".to_string() });
    }

    // C. 尝试 Zebra ZPL (指令 ~HI)
    if let Some(model) = get_zpl_hi_info(ip, timeout_ms).await {
        return Some(PrinterInfo { ip, model, source: "ZPL".to_string() });
    }

    // D. 尝试 SNMP
    if let Some(model) = get_snmp_info(ip).await {
        return Some(PrinterInfo { ip, model, source: "SNMP".to_string() });
    }

    // E. 兜底：如果端口通了且有数据回显，当作未知设备显示出来
    if let Some(raw) = get_raw_banner(ip, timeout_ms).await {
        return Some(PrinterInfo { ip, model: format!("Raw: {}", raw), source: "Raw Banner".to_string() });
    }

    // 如果彻底沉默，返回 None (被过滤)
    None
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let net: Ipv4Net = match args.network.parse() {
        Ok(n) => n,
        Err(e) => { eprintln!("网段错误: {}", e); return; }
    };

    println!("{} 正在扫描: {} (包含 Zebra SGD 深度检测)", "🚀".green(), net);

    let scan_stream = stream::iter(net.hosts())
        .map(|ip| {
            let t = args.timeout_ms;
            async move { scan_target(IpAddr::V4(ip), t).await }
        })
        .buffer_unordered(args.concurrency);

    let mut results: Vec<_> = scan_stream
        .filter_map(|res| async { res })
        .collect()
        .await;

    results.sort_by_key(|k| k.ip);

    println!("\n{}", "--- 扫描结果 ---".yellow());
    if results.is_empty() {
        println!("未发现有效设备。");
        println!("建议: 检查打印机是否跨网段，或防火墙是否拦截了非标准协议。");
    } else {
        for printer in results {
            println!("🖨️  Found: {}", printer.ip.to_string().cyan().bold());
            println!("   └─ Model: {} ({})", printer.model.green().bold(), printer.source);
            println!();
        }
    }
}