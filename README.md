# tron-brute

TRON 私钥暴力破解工具 — 用 Rust 实现，基于 `k256` (secp256k1) + `tiny-keccak` (Keccak-256)。

## 用途

在已知私钥片段（含未知位 `?`）的情况下，通过暴力枚举恢复完整私钥。
用于 [30million.love](https://30million.love) 寻宝挑战。

## 用法

```bash
# 编译
cargo build --release

# 运行（模板中 ? 表示未知位）
./target/release/tron_brute <模板64位hex> <TRON地址> [线程数]

# 示例：测试已知私钥 k=1
./target/release/tron_brute \
  0000000000000000000000000000000000000000000000000000000000000001 \
  TMVQGm1qAQYVdetCeGRRkTWYYrLXtD3qmc

# 示例：暴力破解 4 个未知位
./target/release/tron_brute \
  f62ef022b46823e1f??????????cf28e557037a26694e064 \
  TGXFM77n7Ekh8d2V51uPRrTgNbo7ipZQ5L \
  16
```

## 性能

- 单线程: ~8,000 key/s
- 16 线程: ~8,000 key/s (受内存带宽限制)
- 最大可处理: ≤15 个未知位 (16^15 ≈ 1.15×10^18)

## 测试

```bash
cargo test
```

## 依赖

- [k256](https://crates.io/crates/k256) — secp256k1 椭圆曲线运算
- [tiny-keccak](https://crates.io/crates/tiny-keccak) — Keccak-256 哈希
