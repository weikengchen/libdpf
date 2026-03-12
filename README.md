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

## Usage as Rust Dependency

Add this to your `Cargo.toml`:

```toml
[dependencies]
libdpf = { git = "https://github.com/weikengchen/libdpf.git" }
```

Or to use a specific branch:

```toml
[dependencies]
libdpf = { git = "https://github.com/weikengchen/libdpf.git", branch = "main" }
```

## Usage as TypeScript/JavaScript Dependency

Add this to your `package.json`:

```json
{
  "dependencies": {
    "libdpf": "github:weikengchen/libdpf#main"
  }
}
```

Or with npm:

```bash
npm install weikengchen/libdpf
```

Or with yarn:

```bash
yarn add weikengchen/libdpf
```

The TypeScript package will be automatically built from `libdpf-ts/` during installation.

## References

- Boyle et al. "Function Secret Sharing: Improvements and Extensions" CCS'16
- Frank Wang et al. "Splinter: Practical Private Queries on Public Data" NSDI'17

## License

OpenSSL-compatible licensing. See individual files for details.