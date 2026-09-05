# TRON 私钥模板暴力搜索工具

## 两个版本

### 1. 高性能版（推荐）— 使用 k256 + tiny-keccak
- 源码：`main.rs` + `Cargo.toml`
- 预编译 Linux x64 二进制：`tron_brute_linux_x64`（约 6.8 MB）
- 实测（2 核）：约 **35,000 key/s**（单核约 1.7 万）
- 需要：Rust 1.70+ 编译，或直接跑预编译二进制

编译：
```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
./target/release/tron_brute <模板> <TRON地址> [线程数]
```

### 2. 纯手写版（无外部依赖）— pure_no_deps/
- 零依赖，可直接 cargo build
- 速度约 160–330 key/s（2 核），正确性已验证
- 适合无网络或学习用途

## 用法（两个版本相同）

```
tron_brute <模板64位hex,?未知> <TRON地址> [线程数]
```

示例：
```
./tron_brute_linux_x64 000000000000000000000000000000000000000000000000000000000000000? TMVQGm1qAQYVdetCeGRRkTWYYrLXtD3qmc 8
```

## 注意
- 缺位建议 ≤ 8（CPU），更多请用 GPU 工具
- 预编译二进制仅限 Linux x86_64
- Windows/macOS 请自行 cargo build --release
