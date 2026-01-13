<div align="center">

<p align="center">
  <img src="docs/blitzping_logo.png?raw=true" alt="Blitzping's logo" width="500">
</p>

  <h1><code>Blitzping</code></h1>

  <p>
    <strong>A very high-speed, configurable, and portable packet-crafting utility optimized for embedded devices</strong>
  </p>

  
</div>

***

# Blitzping: Ultra-Fast Packet Crafter & Traceroute Utility

Blitzping is a high-performance packet crafting and network probing tool designed for low-latency, high-throughput operation. This project extends the original Blitzping utility with a DPDK-based kernel-bypass transmission backend and a TTL-based traceroute mode with real-time RTT measurement and visualization.

## Key Features
- **DPDK-based packet transmission** with zero-copy, kernel-bypass I/O
- **High-rate packet crafting** with precise timing control
- **TTL-based traceroute mode** using UDP probes and ICMP feedback
- **Real-time hop-by-hop RTT measurement and GUI visualization**
- Modular design supporting both POSIX sockets and DPDK datapaths

## System Design
### DPDK Integration
The traditional socket-based UDP stack was replaced with a DPDK-powered datapath. Packet buffers are allocated from hugepage-backed memory pools and transmitted directly from user space using poll-mode drivers, eliminating kernel context switches and buffer copies.

Key components:
- DPDK Environment Abstraction Layer (EAL)
- VFIO-PCI NIC access
- Poll-mode drivers for low-latency packet I/O

### Traceroute Implementation
The traceroute module sends UDP probes with incrementing TTL values and listens for ICMP responses (`Time Exceeded` and `Destination Unreachable`) to identify intermediate hops. Per-hop RTTs are computed and visualized dynamically.

## Performance Evaluation
The DPDK backend significantly improves throughput compared to the POSIX implementation:

| Configuration        | TXpps (avg) | TXbps (avg) | Avg Latency | Observation |
|----------------------|-------------|-------------|-------------|-------------|
| Normal (1 thread)    | ~105k       | ~23.7 Mbps  | 5–6 µs      | Kernel-limited baseline |
| Normal (20 threads)  | ~5.8k       | ~1.2 Mbps   | 19–25 µs    | Thread contention |
| DPDK (1 thread)      | ~472k       | ~159 Mbps   | —           | 4.5× throughput gain |
| DPDK (20 threads)    | ~14k        | ~4.8 Mbps   | —           | Queue contention |

## Traceroute Results
![tracert_gui_2](https://github.com/user-attachments/assets/680e6773-fd73-489e-9814-a31bed77aba7)


Usage: 
`blitzping <num. threads> <source IP/CIDR> <dest. IP:Port>` \
Example: `./blitzping 4 192.168.123.123/19 10.10.10.10:80` (this would send TCP SYN packets to `10.10.10.10`'s port `80` from a randomly chosen source IP within an entire range of `192.168.96.0` to `192.168.127.255`, using `4` threads.)

[^1]: To compile under C99, supply `C_STD=c99` to the makefile; this will disable C11 threads but POSIX threads will continue to remain usable, independently.

### Install the LLVM toolchain (if you do not already have it):
(LLVM/Clang, LLVM Linker, and LLVM-strip)
```
apt install llvm clang
apt install lld
apt install llvm-binutils
```

## A) If you wish to only compile for your own machine (i.e., host and target are the same), you can run `make` without any additional options:

```
make
```

The compiler will then create an executable for your target device in the `./out` directory. 

As a final and optional post-processing step, you could strip the debuginfo symbols out of the compiled program and reduce its size:
```
make strip
```

## B) Cross-Compilation (sample for a Debian 12 host and MIPS32r2 target)

#### 1. Install your host's compiler runtime (`compiler-rt` *OR* `libgcc`) for the target machine's architecture:

```
apt install libclang-rt-dev:mips
```
*OR*
```
apt install libgcc1-mips-cross
```

While packages of common architectures, such as x86_64 and arm64, are widely supported on desktop-based Linux distros, Debian (for example) does not provide packages for older embedded targets like 32-bit MIPS\[eb\].  In those cases, if you are not able to manually acquire LLVM's `compile-rt:mips` for that architecture, you could always `apt install libgcc1-mips-cross` for libgcc.

### 2. Then, simply specify your ["target triplet"](https://wiki.osdev.org/Target_Triplet) in make; for example, a soft-float big-endian MIPS running Linux (OpenWRT) with musl libc would be as follows:
```
make TARGET=mips-openwrt-linux-muslsf
```
**Make sure that you specify the correct libc (e.g., `musl`, `gnu`, `uclibc`) _and_ whether or not it lacks an FPU (i.e., if it is soft-float and requires an `sf` suffix to libc).**

Optionally, you can specify the target's sub-architecture to optimize specifically for it:
```
make TARGET=mips-linux-muslsf SUBARCH=mips32r2
```

(As mentioned earlier, you could also `apt install gcc-mips-linux-gnu` and skip LLVM/Clang altogether, if you really want to.)


## Technologies Used
- C / C++
- DPDK
- Raw sockets, UDP, ICMP
- Linux networking (VFIO, hugepages)
- GUI-based visualization

## Attribution
This project extends the original Blitzping packet crafter.  
Core enhancements, DPDK porting, traceroute logic, and performance evaluation were implemented as part of a Computer Networks project.



## License

Blitzping's source code is licensed under the GNU General Public License v3.0 or later ("GPLv3+"), Copyright (C) 2024 Fereydoun Memarzanjany.  Blitzping comes with ABSOLUTELY NO WARRANTY.  Blitzping is free software, and you are welcome to redistribute it under certain conditions; see the GPLv3+.  If you wish to report a bug or contribute to this project, visit this repository: https://github.com/Thraetaona/Blitzping

