//! TRON 私钥寻宝 — 纯 Rust 正确实现（无外部依赖）
//! 用法: tron_brute <模板64位hex,?未知> <TRON地址> [线程数]

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

// ==================== U256 ====================
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U256(pub [u64; 4]); // little-endian limbs

impl U256 {
    const ZERO: Self = Self([0; 4]);
    const ONE: Self = Self([1, 0, 0, 0]);
    const P: Self = Self([
        0xFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ]);
    const GX: Self = Self([
        0x59F2815B16F81798,
        0x029BFCDB2DCE28D9,
        0x55A06295CE870B07,
        0x79BE667EF9DCBBAC,
    ]);
    const GY: Self = Self([
        0x9C47D08FFB10D4B8,
        0xFD17B448A6855419,
        0x5DA4FBFC0E1108A8,
        0x483ADA7726A3C465,
    ]);

    fn from_be_bytes(b: &[u8; 32]) -> Self {
        Self([
            u64::from_be_bytes(b[24..32].try_into().unwrap()),
            u64::from_be_bytes(b[16..24].try_into().unwrap()),
            u64::from_be_bytes(b[8..16].try_into().unwrap()),
            u64::from_be_bytes(b[0..8].try_into().unwrap()),
        ])
    }

    fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.0[3].to_be_bytes());
        out[8..16].copy_from_slice(&self.0[2].to_be_bytes());
        out[16..24].copy_from_slice(&self.0[1].to_be_bytes());
        out[24..32].copy_from_slice(&self.0[0].to_be_bytes());
        out
    }

    fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    fn bit(&self, i: usize) -> bool {
        i < 256 && ((self.0[i / 64] >> (i % 64)) & 1) == 1
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            if self.0[i] != other.0[i] {
                return self.0[i].cmp(&other.0[i]);
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl std::ops::Add for U256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut r = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = self.0[i] as u128 + rhs.0[i] as u128 + carry;
            r[i] = s as u64;
            carry = s >> 64;
        }
        Self(r)
    }
}

impl std::ops::Sub for U256 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let mut r = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = self.0[i] as i128 - rhs.0[i] as i128 - borrow;
            if diff < 0 {
                r[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                r[i] = diff as u64;
                borrow = 0;
            }
        }
        Self(r)
    }
}

// ==================== Field arithmetic ====================
fn mod_add(a: U256, b: U256) -> U256 {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = a.0[i] as u128 + b.0[i] as u128 + carry;
        r[i] = s as u64;
        carry = s >> 64;
    }
    let mut res = U256(r);
    if carry != 0 {
        // +C where C = 0x1000003D1
        let mut c = 0x1000003D1u128;
        for i in 0..4 {
            let s = res.0[i] as u128 + c;
            res.0[i] = s as u64;
            c = s >> 64;
            if c == 0 {
                break;
            }
        }
    }
    if res >= U256::P {
        res = res - U256::P;
    }
    res
}

fn mod_sub(a: U256, b: U256) -> U256 {
    if a >= b {
        a - b
    } else {
        // a - b + P
        let mut r = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = a.0[i] as i128 - b.0[i] as i128 - borrow;
            if diff < 0 {
                r[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                r[i] = diff as u64;
                borrow = 0;
            }
        }
        // r is a-b under 2^64 limbs (negative), add P
        let mut res = U256(r);
        let mut carry = 0u128;
        for i in 0..4 {
            let s = res.0[i] as u128 + U256::P.0[i] as u128 + carry;
            res.0[i] = s as u64;
            carry = s >> 64;
        }
        // result should be < P
        if res >= U256::P {
            res = res - U256::P;
        }
        res
    }
}

fn mod_mul(a: U256, b: U256) -> U256 {
    // schoolbook into 8 limbs
    let mut p = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let cur = p[i + j] as u128 + a.0[i] as u128 * b.0[j] as u128 + carry;
            p[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + 4;
        while carry > 0 && k < 8 {
            let cur = p[k] as u128 + carry;
            p[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }

    // reduce: hi * 2^256 ≡ hi * C (mod P), C = 0x1000003D1
    let mut lo = U256([p[0], p[1], p[2], p[3]]);
    let mut hi = U256([p[4], p[5], p[6], p[7]]);
    let c = 0x1000003D1u64;

    for _ in 0..6 {
        if hi.is_zero() {
            break;
        }
        // hi * C
        let mut t = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..4 {
            let cur = hi.0[i] as u128 * c as u128 + carry;
            t[i] = cur as u64;
            carry = cur >> 64;
        }
        t[4] = carry as u64;

        hi = U256([t[4], 0, 0, 0]);
        let add = U256([t[0], t[1], t[2], t[3]]);

        // lo += add
        let mut carry2 = 0u128;
        for i in 0..4 {
            let s = lo.0[i] as u128 + add.0[i] as u128 + carry2;
            lo.0[i] = s as u64;
            carry2 = s >> 64;
        }
        if carry2 != 0 {
            // add 1 to hi
            let mut c3 = 1u128;
            for i in 0..4 {
                let s = hi.0[i] as u128 + c3;
                hi.0[i] = s as u64;
                c3 = s >> 64;
                if c3 == 0 {
                    break;
                }
            }
        }
    }

    if lo >= U256::P {
        lo = lo - U256::P;
    }
    if lo >= U256::P {
        lo = lo - U256::P;
    }
    lo
}

fn mod_inv(a: U256) -> U256 {
    // a^(P-2)
    let exp = U256([
        0xFFFFFFFEFFFFFC2D,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ]);
    let mut result = U256::ONE;
    let mut base = a;
    for i in 0..256 {
        if exp.bit(i) {
            result = mod_mul(result, base);
        }
        base = mod_mul(base, base);
    }
    result
}

// ==================== Affine EC ====================
#[derive(Clone, Copy)]
struct Point {
    x: U256,
    y: U256,
    infinity: bool,
}

impl Point {
    const INF: Self = Self {
        x: U256::ZERO,
        y: U256::ZERO,
        infinity: true,
    };
    fn g() -> Self {
        Self {
            x: U256::GX,
            y: U256::GY,
            infinity: false,
        }
    }
}

fn point_double(p: Point) -> Point {
    if p.infinity || p.y.is_zero() {
        return Point::INF;
    }
    let xx = mod_mul(p.x, p.x);
    let three_xx = mod_add(mod_add(xx, xx), xx);
    let two_y = mod_add(p.y, p.y);
    let lambda = mod_mul(three_xx, mod_inv(two_y));
    let x3 = mod_sub(mod_mul(lambda, lambda), mod_add(p.x, p.x));
    let y3 = mod_sub(mod_mul(lambda, mod_sub(p.x, x3)), p.y);
    Point {
        x: x3,
        y: y3,
        infinity: false,
    }
}

fn point_add(p: Point, q: Point) -> Point {
    if p.infinity {
        return q;
    }
    if q.infinity {
        return p;
    }
    if p.x == q.x {
        if p.y == q.y {
            return point_double(p);
        }
        return Point::INF;
    }
    let lambda = mod_mul(mod_sub(q.y, p.y), mod_inv(mod_sub(q.x, p.x)));
    let x3 = mod_sub(mod_sub(mod_mul(lambda, lambda), p.x), q.x);
    let y3 = mod_sub(mod_mul(lambda, mod_sub(p.x, x3)), p.y);
    Point {
        x: x3,
        y: y3,
        infinity: false,
    }
}

fn scalar_mult(k: U256) -> Point {
    let mut r = Point::INF;
    let mut b = Point::g();
    for i in 0..256 {
        if k.bit(i) {
            r = point_add(r, b);
        }
        b = point_double(b);
    }
    r
}

// ==================== Keccak-256 (correct RC) ====================
const KECCAK_RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080, // <-- this was wrong before (was 8000)
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const KECCAK_ROT: [usize; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

fn rol64(x: u64, n: usize) -> u64 {
    if n == 0 {
        x
    } else {
        (x << n) | (x >> (64 - n))
    }
}

fn keccakf(st: &mut [u64; 25]) {
    for round in 0..24 {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ rol64(c[(x + 1) % 5], 1);
        }
        for x in 0..5 {
            for y in 0..5 {
                st[x + 5 * y] ^= d[x];
            }
        }
        // ρ + π
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rol64(st[x + 5 * y], KECCAK_ROT[x + 5 * y]);
            }
        }
        // χ
        for x in 0..5 {
            for y in 0..5 {
                st[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
            }
        }
        // ι
        st[0] ^= KECCAK_RC[round];
    }
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut st = [0u64; 25];
    let rate = 136;
    let mut offset = 0;
    let len = input.len();

    while offset + rate <= len {
        for i in 0..rate {
            st[i / 8] ^= (input[offset + i] as u64) << (8 * (i % 8));
        }
        keccakf(&mut st);
        offset += rate;
    }

    let mut block = [0u8; 136];
    let rem = len - offset;
    if rem > 0 {
        block[..rem].copy_from_slice(&input[offset..]);
    }
    block[rem] ^= 0x01;
    block[rate - 1] ^= 0x80;

    for i in 0..rate {
        st[i / 8] ^= (block[i] as u64) << (8 * (i % 8));
    }
    keccakf(&mut st);

    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = ((st[i / 8] >> (8 * (i % 8))) & 0xff) as u8;
    }
    out
}

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

// ==================== Address ====================
fn priv_to_tron_addr20(priv_be: &[u8; 32]) -> [u8; 20] {
    let k = U256::from_be_bytes(priv_be);
    let pt = scalar_mult(k);
    if pt.infinity {
        return [0u8; 20];
    }
    let mut pub_bytes = [0u8; 64];
    pub_bytes[..32].copy_from_slice(&pt.x.to_be_bytes());
    pub_bytes[32..].copy_from_slice(&pt.y.to_be_bytes());
    let digest = keccak256(&pub_bytes);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    out
}

fn priv_to_tron_address(priv_be: &[u8; 32]) -> String {
    let addr20 = priv_to_tron_addr20(priv_be);
    let mut payload = Vec::with_capacity(25);
    payload.push(0x41);
    payload.extend_from_slice(&addr20);
    let checksum = &keccak256(&payload)[..4];
    payload.extend_from_slice(checksum);
    b58encode(&payload)
}

// ==================== main ====================
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("用法: {} <模板64位hex,?未知> <TRON地址> [线程数]", args[0]);
        eprintln!(
            "示例: {} 000000000000000000000000000000000000000000000000000000000000000? TMVQGm1qAQYVdetCeGRRkTWYYrLXtD3qmc 4",
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
    if nunk > 12 {
        eprintln!("缺位过多（建议 ≤12）");
        std::process::exit(1);
    }

    let raw = b58decode(target).expect("Base58解码失败");
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

            for combo in start..start + count {
                if stop.load(Ordering::Relaxed) {
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
                if priv_to_tron_addr20(&priv_bytes) == target20 {
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
        thread::sleep(std::time::Duration::from_millis(400));
        let d = done.load(Ordering::Relaxed);
        let f = found.load(Ordering::Relaxed);
        if d > last || d >= total || f != u64::MAX {
            let el = t0.elapsed().as_secs_f64();
            let rate = if el > 0.0 { d as f64 / el } else { 0.0 };
            eprint!(
                "\r  已测 {:>12} / {:>12}  {:.1} key/s  elapsed {:.1}s",
                d, total, rate, el
            );
            io::stderr().flush().ok();
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
        eprintln!(
            "   耗时: {:.1}s",
            elapsed.as_secs_f64()
        );
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
    fn test_keccak_empty() {
        let result = keccak256(b"");
        let expected = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(result, expected, "keccak empty mismatch");
    }

    #[test]
    fn test_keccak_hello() {
        let result = keccak256(b"hello");
        let expected = [
            0x1c, 0x8a, 0xff, 0x95, 0x06, 0x85, 0xc2, 0xed, 0x4b, 0xc3, 0x17, 0x4f, 0x34, 0x72,
            0x28, 0x7b, 0x56, 0xd9, 0x51, 0x7b, 0x9c, 0x94, 0x81, 0x27, 0x31, 0x9a, 0x09, 0xa7,
            0xa3, 0x6d, 0xea, 0xc8,
        ];
        assert_eq!(result, expected, "keccak hello mismatch");
    }

    #[test]
    fn test_g_coordinates() {
        let pt = scalar_mult(U256::ONE);
        assert!(!pt.infinity);
        let px = pt.x.to_be_bytes();
        let py = pt.y.to_be_bytes();
        assert_eq!(
            px,
            [
                0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
                0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2,
                0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
            ]
        );
        assert_eq!(
            py,
            [
                0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e,
                0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47,
                0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
            ]
        );
    }

    #[test]
    fn test_priv1_addr() {
        let mut pb = [0u8; 32];
        pb[31] = 1;
        let addr = priv_to_tron_address(&pb);
        assert_eq!(addr, "TMVQGm1qAQYVdetCeGRRkTWYYrLXtD3qmc");
    }

    #[test]
    fn test_priv2_addr() {
        let mut pb = [0u8; 32];
        pb[31] = 2;
        let addr = priv_to_tron_address(&pb);
        assert_eq!(addr, "TDvSsdrNM5eeXNL3czpa6AxLDHZA7c1zjf");
    }
}
