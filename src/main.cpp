#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

static uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
static uint32_t le32(const uint8_t* p) { return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24); }
static uint32_t be32(const uint8_t* p) { return static_cast<uint32_t>(p[3]) | (static_cast<uint32_t>(p[2]) << 8) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[0]) << 24); }

static std::string ipv4(const uint8_t* p) {
    std::ostringstream out;
    out << static_cast<int>(p[0]) << '.' << static_cast<int>(p[1]) << '.' << static_cast<int>(p[2]) << '.' << static_cast<int>(p[3]);
    return out.str();
}

static std::string dns_name(const uint8_t* data, std::size_t len, std::size_t offset) {
    std::ostringstream out;
    bool first = true;
    while (offset < len) {
        const auto n = data[offset++];
        if (n == 0) break;
        if ((n & 0xC0) != 0 || offset + n > len) return {};
        if (!first) out << '.';
        first = false;
        for (uint8_t i = 0; i < n; ++i) out << static_cast<char>(data[offset++]);
    }
    return out.str();
}

struct Stats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    std::map<std::string, std::uint64_t> protocols;
    std::map<std::string, std::uint64_t> talkers;
    std::map<unsigned, std::uint64_t> ports;
    std::map<std::string, std::uint64_t> dns_queries;
};

static void count_packet(const std::vector<uint8_t>& packet, Stats& s) {
    ++s.packets; s.bytes += packet.size();
    if (packet.size() < 14) { ++s.protocols["truncated"]; return; }
    const auto etherType = be16(packet.data() + 12);
    if (etherType != 0x0800) { ++s.protocols["non-ipv4"]; return; }
    if (packet.size() < 34) { ++s.protocols["truncated-ipv4"]; return; }
    const std::size_t ip = 14;
    const std::size_t ihl = static_cast<std::size_t>(packet[ip] & 0x0F) * 4;
    if (ihl < 20 || packet.size() < ip + ihl) { ++s.protocols["invalid-ipv4"]; return; }
    const auto src = ipv4(packet.data() + ip + 12);
    const auto dst = ipv4(packet.data() + ip + 16);
    ++s.talkers[src]; ++s.talkers[dst];
    const uint8_t proto = packet[ip + 9];
    const std::size_t transport = ip + ihl;
    if (proto == 6 && packet.size() >= transport + 4) {
        ++s.protocols["tcp"];
        ++s.ports[be16(packet.data() + transport)];
        ++s.ports[be16(packet.data() + transport + 2)];
    } else if (proto == 17 && packet.size() >= transport + 8) {
        ++s.protocols["udp"];
        const auto sport = be16(packet.data() + transport);
        const auto dport = be16(packet.data() + transport + 2);
        ++s.ports[sport]; ++s.ports[dport];
        if ((sport == 53 || dport == 53) && packet.size() >= transport + 20) {
            const auto flags = be16(packet.data() + transport + 10);
            if ((flags & 0x8000) == 0) {
                const auto name = dns_name(packet.data() + transport + 8, packet.size() - (transport + 8), 12);
                if (!name.empty()) ++s.dns_queries[name];
            }
        }
    } else if (proto == 1) ++s.protocols["icmp"];
    else ++s.protocols["other-ip"];
}

static std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (char c : value) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c == '\n') out << "\\n";
        else out << c;
    }
    return out.str();
}

template<typename K>
static void json_map(std::ostream& out, const std::map<K, std::uint64_t>& m) {
    out << '{'; bool first = true;
    for (const auto& [key, value] : m) {
        if (!first) out << ',';
        first = false;
        std::ostringstream k; k << key;
        out << '"' << json_escape(k.str()) << "\":" << value;
    }
    out << '}';
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: packetlens <capture.pcap> [--json output.json]\n";
        return 2;
    }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) { std::cerr << "Cannot open capture.\n"; return 2; }
    std::array<uint8_t, 24> global{};
    if (!in.read(reinterpret_cast<char*>(global.data()), global.size())) { std::cerr << "Invalid PCAP header.\n"; return 2; }
    const uint32_t magicLe = le32(global.data());
    bool little;
    if (magicLe == 0xa1b2c3d4U || magicLe == 0xa1b23c4dU) little = true;
    else if (magicLe == 0xd4c3b2a1U || magicLe == 0x4d3cb2a1U) little = false;
    else { std::cerr << "Unsupported file: classic PCAP required.\n"; return 2; }
    const auto read32 = [little](const uint8_t* p) { return little ? le32(p) : be32(p); };
    Stats stats;
    while (true) {
        std::array<uint8_t, 16> header{};
        if (!in.read(reinterpret_cast<char*>(header.data()), header.size())) break;
        const auto inclLen = read32(header.data() + 8);
        if (inclLen > 16U * 1024U * 1024U) { std::cerr << "Unreasonable packet length.\n"; return 2; }
        std::vector<uint8_t> packet(inclLen);
        if (!in.read(reinterpret_cast<char*>(packet.data()), static_cast<std::streamsize>(packet.size()))) { std::cerr << "Truncated packet.\n"; return 2; }
        count_packet(packet, stats);
    }

    std::cout << "Packets: " << stats.packets << "\nBytes: " << stats.bytes << "\nProtocols:\n";
    for (const auto& [name, count] : stats.protocols) std::cout << "  " << name << ": " << count << '\n';
    std::cout << "Top talkers:\n";
    std::vector<std::pair<std::string, std::uint64_t>> talkers(stats.talkers.begin(), stats.talkers.end());
    std::sort(talkers.begin(), talkers.end(), [](const auto& a, const auto& b){ return a.second > b.second; });
    for (std::size_t i = 0; i < std::min<std::size_t>(10, talkers.size()); ++i) std::cout << "  " << talkers[i].first << ": " << talkers[i].second << '\n';
    if (!stats.dns_queries.empty()) {
        std::cout << "DNS queries:\n";
        for (const auto& [name, count] : stats.dns_queries) std::cout << "  " << name << ": " << count << '\n';
    }

    for (int i = 2; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--json") {
            std::ofstream out(argv[i + 1]);
            out << "{\"packets\":" << stats.packets << ",\"bytes\":" << stats.bytes << ",\"protocols\":";
            json_map(out, stats.protocols); out << ",\"talkers\":"; json_map(out, stats.talkers);
            out << ",\"ports\":"; json_map(out, stats.ports); out << ",\"dnsQueries\":"; json_map(out, stats.dns_queries); out << "}\n";
        }
    }
    return 0;
}
