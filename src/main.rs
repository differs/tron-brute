//! TRON 私钥寻宝 — Rust CPU 暴力破解
//! 用法: tron_brute <模板64位hex,?未知> <TRON地址> [线程数]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey, Scalar, ProjectivePoint, Secp256k1};
use k256::elliptic_curve::ops::Mul;

fn keccak256(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Keccak, Hasher};
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn b58decode(s: &str) -> Option<Vec<u8>> {
    const ALPH: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num = vec![0u8; 48];
    let mut numlen = 0usize;
    let mut zero = 0usize;
    while s.as_bytes().get(zero) == Some(&b'1') { zero += 1; }
    for &c in s.as_bytes() {
        let d = ALPH.iter().position(|&x| x == c)? as u64;
        let mut carry = d;
        for i in 0..numlen {
            let cur = (num[i] as u64) * 58 + carry;
            num[i] = cur as u8; carry = cur >> 8;
        }
        while carry > 0 {
            if numlen >= num.len() { return None; }
            num[numlen] = (carry % 256) as u8; carry /= 256; numlen += 1;
        }
    }
    let mut result = vec![0u8; zero];
    for i in 0..numlen.min(25) { result.push(num[numlen - 1 - i]); }
    Some(result)
}

fn b58encode(data: &[u8]) -> String {
    const ALPH: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Count leading zeros
    let zero_count = data.iter().take_while(|&&b| b == 0).count();
    // Convert to base58 using repeated division
    let mut num: Vec<u8> = data[zero_count..].to_vec();
    let mut digits = Vec::new();
    while !num.is_empty() {
        let mut rem = 0u64;
        let mut new_num = Vec::new();
        for &byte in &num {
            let cur = rem * 256 + byte as u64;
            new_num.push((cur / 58) as u8);
            rem = cur % 58;
        }
        digits.push(ALPH[rem as usize]);
        // Remove leading zeros from new_num
        let start = new_num.iter().take_while(|&&b| b == 0).count();
        num = if start >= new_num.len() { Vec::new() } else { new_num[start..].to_vec() };
    }
    let mut result = String::new();
    for _ in 0..zero_count { result.push('1'); }
    for &d in digits.iter().rev() { result.push(d as char); }
    result
}

fn hex_val(c: u8) -> u8 {
    match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, b'A'..=b'F' => c - b'A' + 10, _ => 0 }
}

fn priv_to_pub_addr_safe(priv_bytes: &[u8; 32]) -> Option<String> {
    let sk = SecretKey::from_bytes(priv_bytes.into()).ok()?;
    Some(priv_to_pub_addr(priv_bytes))
}

fn priv_to_pub_addr(priv_bytes: &[u8; 32]) -> String {
    let sk = SecretKey::from_bytes(priv_bytes.into()).expect("invalid key");
    let pk: PublicKey = sk.public_key();
    let point = pk.to_encoded_point(false); // uncompressed, no 0x04 prefix
    let pub_bytes = point.as_bytes(); // 65 bytes: 0x04 + x + y
    let pub_xy = &pub_bytes[1..]; // skip 0x04, 64 bytes
    let digest = keccak256(pub_xy);
    let addr20 = &digest[12..];
    let payload: Vec<u8> = std::iter::once(0x41).chain(addr20.iter().cloned()).collect();
    let checksum = &keccak256(&payload)[..4];
    let full: Vec<u8> = payload.iter().chain(checksum.iter()).cloned().collect();
    b58encode(&full)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("用法: {} <模板64位hex,?未知> <TRON地址> [线程数]", args[0]);
        eprintln!("例:   {} f62??? TGXFM77n7Ekh8d2V51uPRrTgNbo7ipZQ5L 16", args[0]);
        std::process::exit(1);
    }
    let tmpl = args[1].to_lowercase();
    let target = &args[2];
    let nthreads = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let nthreads = if nthreads == 0 { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(16) } else { nthreads };
    
    if tmpl.len() != 64 || !tmpl.chars().all(|c| c.is_ascii_hexdigit() || c == '?') {
        eprintln!("模板必须是64位hex (?为未知)"); std::process::exit(1);
    }
    
    let positions: Vec<usize> = tmpl.chars().enumerate().filter(|(_, c)| *c == '?').map(|(i, _)| i).collect();
    let nunk = positions.len();
    if nunk > 15 { eprintln!("缺位过多 (>15)"); std::process::exit(1); }
    
    let raw = b58decode(target).expect("base58解码失败");
    if raw.len() < 21 { eprintln!("目标地址解析失败"); std::process::exit(1); }
    let target20: [u8; 20] = raw[1..21].try_into().unwrap();
    
    let total: u64 = 1u64 << (nunk * 4);
    
    eprintln!("模板: {}", tmpl);
    eprintln!("缺位: {}处 = 16^{} = {} 组合", nunk, nunk, total);
    eprintln!("目标: {}", target);
    eprint!("target20: "); for b in &target20 { eprint!("{:02x}", b); } eprintln!();
    eprintln!("线程: {}", nthreads); eprintln!();
    
    let found = Arc::new(AtomicU64::new(u64::MAX));
    let done = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let t0 = Instant::now();
    
    let per_thread = total / nthreads as u64;
    let remainder = total % nthreads as u64;
    let mut handles = Vec::new();
    
    for t in 0..nthreads {
        let start = t as u64 * per_thread;
        let count = per_thread + if t < remainder as usize { 1 } else { 0 };
        if start >= total { break; }
        
        let tmpl = tmpl.clone();
        let positions = positions.clone();
        let target20 = target20;
        let found = Arc::clone(&found);
        let done = Arc::clone(&done);
        let stop = Arc::clone(&stop);
        let target_str = target.clone();
        
        handles.push(thread::spawn(move || {
            let mut hex = [0u8; 65];
            for (i, c) in tmpl.chars().enumerate() { hex[i] = c as u8; }
            let hex_chars = b"0123456789abcdef";
            
            for combo in start..start + count {
                if stop.load(Ordering::Relaxed) { return; }
                
                let mut tmp = combo;
                for &pos in &positions {
                    hex[pos] = hex_chars[(tmp & 0xf) as usize];
                    tmp >>= 4;
                }
                
                let mut priv_bytes = [0u8; 32];
                for i in 0..32 { priv_bytes[i] = (hex_val(hex[2*i]) << 4) | hex_val(hex[2*i+1]); }
                
                let addr = match priv_to_pub_addr_safe(&priv_bytes) {
                    Some(a) => a,
                    None => { done.fetch_add(1, Ordering::Relaxed); continue; },
                };
                if addr == target_str {
                    found.store(combo, Ordering::Relaxed);
                    stop.store(true, Ordering::Relaxed);
                    return;
                }
                done.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    
    let mut last = 0u64;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let d = done.load(Ordering::Relaxed);
        let f = found.load(Ordering::Relaxed);
        if d > last || d >= total || f != u64::MAX {
            let el = t0.elapsed().as_secs_f64();
            let rate = if el > 0.0 { d as f64 / el } else { 0.0 };
            eprintln!("\r  已测 {:>12} / {:>12}  {:.1} key/s  elapsed {:.1}s", d, total, rate, el);
            last = d;
        }
        if f != u64::MAX || d >= total { break; }
    }
    
    for h in handles { h.join().ok(); }
    
    let elapsed = t0.elapsed();
    let found_val = found.load(Ordering::Relaxed);
    
    if found_val != u64::MAX {
        let mut hex = [0u8; 65];
        for (i, c) in tmpl.chars().enumerate() { hex[i] = c as u8; }
        let mut tmp = found_val;
        for &pos in &positions { hex[pos] = b"0123456789abcdef"[tmp as usize & 0xf]; tmp >>= 4; }
        hex[64] = 0;
        let priv_str = unsafe { std::str::from_utf8_unchecked(&hex[..64]) };
        eprintln!("\n✅ 找回私钥: {}", priv_str);
        eprintln!("   耗时: {:.1}s, 吞吐: {:.0} key/s", elapsed.as_secs_f64(), found_val as f64 / elapsed.as_secs_f64());
    } else {
        eprintln!("\n❌ 未找回 (耗时 {:.1}s, 已测 {}/{} )", elapsed.as_secs_f64(), done.load(Ordering::Relaxed), total);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_priv1() {
        let mut pb = [0u8; 32]; pb[31] = 1;
        assert_eq!(priv_to_pub_addr(&pb), "TMVQGm1qAQYVdetCeGRRkTWYYrLXtD3qmc");
    }
    
    #[test]
    fn test_priv2() {
        let mut pb = [0u8; 32]; pb[31] = 2;
        assert_eq!(priv_to_pub_addr(&pb), "TDvSsdrNM5eeXNL3czpa6AxLDHZA7c1zjf");
    }
    
    #[test]
    fn test_priv3() {
        let mut pb = [0u8; 32]; pb[31] = 3;
        assert_eq!(priv_to_pub_addr(&pb), "TKTX96CBxr5kvhjsDHcqoiPWZageKfKC8s");
    }
    
    #[test]
    fn test_keccak_empty() {
        let r = keccak256(b"");
        assert_eq!(&r[..], &hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap()[..]);
    }
    
    #[test]
    fn test_keccak_hello() {
        let r = keccak256(b"hello");
        assert_eq!(&r[..], &hex::decode("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8").unwrap()[..]);
    }
}
