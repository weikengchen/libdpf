# libdpf-c

C implementation of 2-server 1-bit Distributed Point Function with cross-platform hardware-accelerated AES support.

## Supported Platforms

- **x86_64/x64**: Uses Intel AES-NI instructions
- **ARM64/Apple Silicon**: Uses ARMv8-A Cryptographic Extension (NEON AES instructions)

## Building

### Linux
```bash
sudo apt-get install cmake libssl-dev
mkdir build && cd build
cmake ..
make
```

### macOS
```bash
brew install cmake openssl
mkdir build && cd build
cmake ..
make
```

## Executables

- `fss` - Self-test program
- `fssgen` - Generate DPF keys: `./fssgen N alpha`
- `fsseval` - Evaluate DPF: `./fsseval N filename`

## References

Based on "Function Secret Sharing: Improvements and Extensions" (Boyle et al., CCS'16)
https://cs.idc.ac.il/~elette/FSS-CCS.pdf