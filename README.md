# libdpf

A template for 2-server 1-bit Distributed Point Function. The construction is from "Function Secret Sharing: Improvements and Extensions" from Boyle et al. 

Paper: https://cs.idc.ac.il/~elette/FSS-CCS.pdf

## Implementations

| Directory | Language | Description |
|-----------|----------|-------------|
| `libdpf-c/` | C | Native implementation with hardware-accelerated AES (x86_64 & ARM64) |
| `libdpf-rust/` | Rust | Rust implementation |
| `libdpf-ts/` | TypeScript | TypeScript implementation |

## Supported Platforms (C Implementation)

The C implementation supports hardware-accelerated AES on:

- **x86_64/x64**: Uses Intel AES-NI instructions
- **ARM64/Apple Silicon**: Uses ARMv8-A Cryptographic Extension (NEON AES instructions)

## Quick Start

```bash
cd libdpf-c
mkdir build && cd build
cmake ..
make
./fss  # Run self-test
```

## References

- Boyle et al. "Function Secret Sharing: Improvements and Extensions" CCS'16
- Frank Wang et al. "Splinter: Practical Private Queries on Public Data" NSDI'17

## License

OpenSSL-compatible licensing. See individual files for details.