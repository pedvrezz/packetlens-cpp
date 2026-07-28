# PacketLens C++

PacketLens is a dependency-free offline analyzer for classic `.pcap` files. It parses Ethernet and IPv4 packets and summarizes TCP, UDP, ICMP, ports, talkers and DNS queries.

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Analyze

```bash
./build/packetlens capture.pcap --json report.json
```

## Scope

The first release intentionally supports classic PCAP with Ethernet link type. PCAP-NG, IPv6, fragmentation reassembly and deep TCP analysis are good future issues.

PacketLens never captures traffic and does not interact with the network. Analyze only captures you are authorized to inspect.
