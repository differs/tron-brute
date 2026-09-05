//! TRON 私钥寻宝 — 高性能版（k256 + tiny-keccak）
//! 用法: tron_brute <模板64位hex,?未知> <TRON地址> [线程数]
//!
//! 本地编译:
//!   cargo build --release
//!   RUSTFLAGS="-C target-cpu=native" cargo build --release

use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, Scalar, SecretKey,
};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tiny_keccak::{Hasher, Keccak};

// ==================== Base58 ====================
fn b58decode(s: &str) -> Option<Vec<u8>> {
    const ALPH: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num = vec![0u8; 48];
    let mut numlen = 0usize;
    let mut zero = 0usize;
    let bytes = s.as_bytes();
    while zero < bytes.len() && bytes[zero] == b'1' {
        zero += 1;
    }
    for &c in bytes {
        let d = ALPH.iter().position(|&x| x == c)? as u64;
        let mut carry = d;
        for i in 0..numlen {
            let cur = num[i] as u64 * 58 + carry;
            num[i] = cur as u8;
            carry = cur >> 8;
        }
        while carry > 0 {
            if numlen >= num.len() {
                return None;
            }
            num[numlen] = (carry % 256) as u8;
            carry /= 256;
            numlen += 1;
        }
    }
    let mut result = vec![0u8; zero];
    for i in 0..numlen {
        result.push(num[numlen - 1 - i]);
    }
    Some(result)
}

fn b58encode(data: &[u8]) -> String {
    const ALPH: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zero_count = data.iter().take_while(|&&b| b == 0).count();
    let mut result = String::with_capacity(zero_count + 50);
    for _ in 0..zero_count {
        result.push('1');
    }

    let mut num = vec![0u64; 40];
    let mut numlen = 0usize;
    for &byte in data {
        let mut carry = byte as u64;
        for i in 0..numlen {
            let cur = (num[i] as u128) * 256 + carry as u128;
            num[i] = cur as u64;
            carry = (cur >> 64) as u64;
        }
        while carry > 0 {
            if numlen >= num.len() {
                break;
            }
            num[numlen] = carry;
            numlen += 1;
            carry = 0;
        }
    }

    let mut tmp = num[..numlen].to_vec();
    let mut tmp_len = numlen;
    loop {
        let mut rem = 0u64;
        for i in (0..tmp_len).rev() {
            let cur = ((rem as u128) << 64) | tmp[i] as u128;
            tmp[i] = (cur / 58) as u64;
            rem = (cur % 58) as u64;
        }
        while tmp_len > 1 && tmp[tmp_len - 1] == 0 {
            tmp_len -= 1;
        }
        result.push(ALPH[rem as usize] as char);
        if tmp_len == 1 && tmp[0] == 0 {
            break;
        }
    }
    result.chars().rev().collect()
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// 私钥字节 → TRON 地址的 20 字节 payload（不含 0x41 和 checksum）
#[inline]
fn priv_to_addr20(priv_be: &[u8; 32]) -> [u8; 20] {
    let sk = match SecretKey::from_slice(priv_be) {
        Ok(s) => s,
        Err(_) => return [0u8; 20], // 无效私钥（>= 曲线阶）直接跳过
    };
    // 使用投影坐标做标量乘，最后转仿射
    let pk = sk.public_key();
    let point = pk.to_encoded_point(false); // uncompressed 65 bytes: 04 || X || Y
    let pub64 = &point.as_bytes()[1..65];

    let hash = keccak256(pub64);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..32]);
    out
}

fn priv_to_tron_address(priv_be: &[u8; 32]) -> String {
    let addr20 = priv_to_addr20(priv_be);
    let mut payload = Vec::with_capacity(25);
    payload.push(0x41);
    payload.extend_from_slice(&addr20);
    let checksum = &keccak256(&payload)[..4];
    payload.extend_from_slice(checksum);
    b58encode(&payload)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("用法: {} <模板64位hex,?未知> <TRON地址> [线程数]", args[0]);
        eprintln!(
            "示例: {} 000000000000000000000000000000000000000000000000000000000000000? TMVQGm1qAQYVdetCeGRRkTWYYrLXtD3qmc 8",
            args[0]
        );
        std::process::exit(1);
    }

    let tmpl = args[1].to_lowercase();
    let target = &args[2];
    let nthreads = args.get(3).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8)
    });

    if tmpl.len() != 64 || !tmpl.chars().all(|c| c.is_ascii_hexdigit() || c == '?') {
        eprintln!("模板必须是64位hex（? 表示未知）");
        std::process::exit(1);
    }

    let positions: Vec<usize> = tmpl
        .chars()
        .enumerate()
        .filter(|(_, c)| *c == '?')
        .map(|(i, _)| i)
        .collect();
    let nunk = positions.len();
    if nunk > 14 {
        eprintln!("缺位过多（>14 不推荐）");
        std::process::exit(1);
    }

    let raw = b58decode(target).expect("Base58 解码失败");
    if raw.len() < 21 {
        eprintln!("目标地址解析失败");
        std::process::exit(1);
    }
    let target20: [u8; 20] = raw[1..21].try_into().expect("地址格式错误");

    let total: u64 = 1u64 << (nunk * 4);
    eprintln!("模板: {}", tmpl);
    eprintln!("缺位: {} 处 = 16^{} = {} 组合", nunk, nunk, total);
    eprintln!("目标: {}", target);
    eprint!("target20: ");
    for b in &target20 {
        eprint!("{:02x}", b);
    }
    eprintln!();
    eprintln!("线程: {}\n", nthreads);

    let found = Arc::new(AtomicU64::new(u64::MAX));
    let done = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let t0 = Instant::now();

    let per_thread = total / nthreads as u64;
    let remainder = total % nthreads as u64;
    let mut handles = Vec::new();

    for t in 0..nthreads {
        let start = t as u64 * per_thread;
        let count = per_thread + if (t as u64) < remainder { 1 } else { 0 };
        if start >= total {
            break;
        }

        let tmpl = tmpl.clone();
        let positions = positions.clone();
        let target20 = target20;
        let found = Arc::clone(&found);
        let done = Arc::clone(&done);
        let stop = Arc::clone(&stop);

        handles.push(thread::spawn(move || {
            let mut hex = [0u8; 64];
            for (i, c) in tmpl.chars().enumerate() {
                hex[i] = c as u8;
            }
            let hex_chars = b"0123456789abcdef";

            // 本地计数，减少原子操作
            let mut local_done = 0u64;
            const REPORT_EVERY: u64 = 4096;

            for combo in start..start + count {
                if stop.load(Ordering::Relaxed) {
                    done.fetch_add(local_done, Ordering::Relaxed);
                    return;
                }

                let mut tmp = combo;
                for &pos in &positions {
                    hex[pos] = hex_chars[(tmp & 0xf) as usize];
                    tmp >>= 4;
                }

                let mut priv_bytes = [0u8; 32];
                for i in 0..32 {
                    priv_bytes[i] = (hex_val(hex[2 * i]) << 4) | hex_val(hex[2 * i + 1]);
                }

                if priv_to_addr20(&priv_bytes) == target20 {
                    found.store(combo, Ordering::Relaxed);
                    stop.store(true, Ordering::Relaxed);
                    done.fetch_add(local_done + 1, Ordering::Relaxed);
                    return;
                }

                local_done += 1;
                if local_done >= REPORT_EVERY {
                    done.fetch_add(local_done, Ordering::Relaxed);
                    local_done = 0;
                }
            }
            done.fetch_add(local_done, Ordering::Relaxed);
        }));
    }

    let mut last = 0u64;
    loop {
        thread::sleep(std::time::Duration::from_millis(300));
        let d = done.load(Ordering::Relaxed);
        let f = found.load(Ordering::Relaxed);
        if d > last || d >= total || f != u64::MAX {
            let el = t0.elapsed().as_secs_f64();
            let rate = if el > 0.0 { d as f64 / el } else { 0.0 };
            eprint!(
                "\r  已测 {:>12} / {:>12}  {:.0} key/s  elapsed {:.1}s",
                d, total, rate, el
            );
            let _ = io::stderr().flush();
            last = d;
        }
        if f != u64::MAX || d >= total {
            break;
        }
    }
    eprintln!();

    for h in handles {
        let _ = h.join();
    }

    let elapsed = t0.elapsed();
    let found_val = found.load(Ordering::Relaxed);

    if found_val != u64::MAX {
        let mut hex = [0u8; 64];
        for (i, c) in tmpl.chars().enumerate() {
            hex[i] = c as u8;
        }
        let mut tmp = found_val;
        for &pos in &positions {
            hex[pos] = b"0123456789abcdef"[(tmp & 0xf) as usize];
            tmp >>= 4;
        }
        let priv_str: String = hex.iter().map(|&b| b as char).collect();

        let mut pb = [0u8; 32];
        for i in 0..32 {
            pb[i] = (hex_val(hex[2 * i]) << 4) | hex_val(hex[2 * i + 1]);
        }
        let addr = priv_to_tron_address(&pb);

        eprintln!("\n✅ 找回私钥: {}", priv_str);
        eprintln!("   验证地址: {}", addr);
        eprintln!("   匹配: {}", if addr == *target { "✅" } else { "❌" });
        eprintln!("   耗时: {:.2}s", elapsed.as_secs_f64());
    } else {
        eprintln!(
            "\n❌ 未找回 (耗时 {:.1}s, 已测 {}/{})",
            elapsed.as_secs_f64(),
            done.load(Ordering::Relaxed),
            total
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priv1() {
        let mut pb = [0u8; 32];
        pb[31] = 1;
        assert_eq!(priv_to_tron_address(&pb), "TMVQGm1qAQYVdetCeGRRkTWYYrLXtD3qmc");
    }

    #[test]
    fn test_priv2() {
        let mut pb = [0u8; 32];
        pb[31] = 2;
        assert_eq!(priv_to_tron_address(&pb), "TDvSsdrNM5eeXNL3czpa6AxLDHZA7c1zjf");
    }
}
