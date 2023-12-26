#include "output.hpp"
#include "addr_conv.hpp"
#include "counter.hpp"
#include <arpa/inet.h>
#include <format>
#include <iomanip>
#include <iostream>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <tuple>
#include <unordered_set>

extern std::unordered_set<std::string> global_mac_list;
extern struct PacketCounter global_counter;

void print_line() { std::cout << "-----------" << std::endl; }

void print_split(std::string s) {
  std::cout << std::endl;
  print_line();
  std::cout << s << std::endl;
  print_line();
}

uint16_t print_eth(struct ether_header *ethhead, bool prt) {

  auto sa = mac_to_str(ethhead->ether_shost);
  auto da = mac_to_str(ethhead->ether_dhost);
  global_mac_list.insert(sa);
  global_mac_list.insert(da);

  uint16_t eth_type = ntohs(ethhead->ether_type);
  if (prt) {
    print_split("Ethernet head");
    print_table("Ethernet Type", eth_type);
    print_table("Source MAC address", sa);
    print_table("Destination MAC address", da);
  }
  return eth_type;
}

std::tuple<uint8_t, unsigned int> print_ip(struct ip *iphead, bool prt) {
  std::string sh(inet_ntoa(iphead->ip_src));
  std::string dh(inet_ntoa(iphead->ip_dst));
  // check if dst is broadcast
  global_counter.ip_bytes += ntohs(iphead->ip_len);
  if (iphead->ip_dst.s_addr == 0xffffffff) {
    global_counter.ipv4_boardcast++;
  }
  if (prt) {
    print_split("IP head:");
    print_table("Source host", sh);
    print_table("Dest host", dh);
  }
  return {iphead->ip_p, iphead->ip_hl * 4};
}

uint8_t print_ipv6(struct ip6_hdr *iphead, bool prt) {
  global_counter.ip_bytes += ntohs(iphead->ip6_ctlun.ip6_un1.ip6_un1_plen);
  char buffer[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &iphead->ip6_src, buffer, INET6_ADDRSTRLEN);
  std::string sh(buffer);
  inet_ntop(AF_INET6, &iphead->ip6_dst, buffer, INET6_ADDRSTRLEN);
  std::string dh(buffer);
  if (prt) {
    print_split("IPv6 head:");
    print_table("Source host", sh);
    print_table("Dest host", dh);
  }
  return iphead->ip6_ctlun.ip6_un1.ip6_un1_nxt;
}

void print_icmp(struct icmphdr *icmp_header) {

  print_split("icmp");

  // 输出 ICMP 类型
  print_table("Type", (unsigned int)icmp_header->type);

  // 输出 ICMP 代码
  print_table("Code", (unsigned int)icmp_header->code);

  // 输出校验和
  print_table("Checksum", ntohs(icmp_header->checksum));
}

void print_tcp(struct tcphdr *tcp_header) {
  print_split("tcp");
  print_table("Source Port", ntohs(tcp_header->source));
  print_table("Destination Port", ntohs(tcp_header->dest));

  // 输出序列号
  print_table("Sequence Number", ntohl(tcp_header->seq));

  print_table("Window Size", ntohs(tcp_header->window));
  // 初始化一个空字符串来存储标志位信息
  std::string flags;

  // 逐个检查标志位
  if (tcp_header->urg)
    flags += "URG ";
  if (tcp_header->ack)
    flags += "ACK ";
  if (tcp_header->psh)
    flags += "PSH ";
  if (tcp_header->rst)
    flags += "RST ";
  if (tcp_header->syn)
    flags += "SYN ";
  if (tcp_header->fin)
    flags += "FIN ";

  // 输出标志位字符串
  print_table("Flags", flags);
  // 输出确认号（如果 ACK 标志位设置了）
  if (tcp_header->ack) {
    print_table("Acknowledgment Number", ntohl(tcp_header->ack_seq));
  }
}

void print_udp(struct udphdr *udp_header) {

  print_split("udp");
  // 输出源端口
  print_table("Source Port", ntohs(udp_header->source));

  // 输出目的端口
  print_table("Destination Port", ntohs(udp_header->dest));

  // 输出UDP长度
  print_table("Length", ntohs(udp_header->len));
}

void print_arp(struct arphdr *arp_header) {
  print_split("arp");
  // 获取发送者和目标的硬件和协议地址
  unsigned char *sender_hardware_address = (unsigned char *)(arp_header + 1);
  unsigned char *sender_protocol_address =
      sender_hardware_address + arp_header->ar_hln;
  unsigned char *target_hardware_address =
      sender_protocol_address + arp_header->ar_pln;
  unsigned char *target_protocol_address =
      target_hardware_address + arp_header->ar_hln;
  std::string sender_hw_addr = mac_to_str(sender_hardware_address);

  std::string target_hw_addr = mac_to_str(target_hardware_address);

  // 转换 IP 地址为可读格式
  char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, sender_protocol_address, sender_ip, sizeof(sender_ip));
  inet_ntop(AF_INET, target_protocol_address, target_ip, sizeof(target_ip));

  // 格式化并输出 ARP 信息
  std::string arp_info;
  if (ntohs(arp_header->ar_op) == ARPOP_REQUEST) {
    arp_info = std::format("Request who-has {} tell {}", target_ip, sender_ip,
                           sizeof(struct arphdr));
  } else if (ntohs(arp_header->ar_op) == ARPOP_REPLY) {
    arp_info = std::format("Reply {} is-at "
                           "{}",
                           sender_ip, mac_to_str(sender_hardware_address));
  }

  std::cout << arp_info << std::endl;
}