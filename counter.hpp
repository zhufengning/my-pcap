#include <ctime>
struct PacketCounter {
  unsigned all, bytes, ip, ip6, ipv4_boardcast, ip_bytes, arp, udp, tcp, icmp,
      icmp_redirect, icmp_destination_unreach, eth_jumbo_frame, eth_runt_frame;

  std::time_t start_time, end_time;
};
