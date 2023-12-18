#include "output.hpp"
#include "addr_conv.hpp"
#include <arpa/inet.h>
#include <iomanip>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <tuple>
#include <unordered_set>

extern std::unordered_set<std::string> global_mac_list;

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
  if (prt) {
    print_split("IP head:");
    print_table("Source host", sh);
    print_table("Dest host", dh);
  }
  return {iphead->ip_p, iphead->ip_hl * 4};
}

uint8_t print_ipv6(struct ip6_hdr *iphead, bool prt) {
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