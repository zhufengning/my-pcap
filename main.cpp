#include "addr_conv.hpp"
#include "cxxopts.hpp"
#include "output.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <errno.h>
#include <format>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_set>

cxxopts::ParseResult opts;

struct PacketCounter {
  unsigned all, udp, tcp, icmp, arp;
} global_counter;

std::unordered_set<std::string> global_mac_list;

void my_handler(int s) {
  printf("Caught signal %d\n", s);
  for (auto v : global_mac_list) {
    std::cout << v << std::endl;
  }
  exit(1);
}

int init() {

  struct sigaction sigIntHandler;

  sigIntHandler.sa_handler = my_handler;
  sigemptyset(&sigIntHandler.sa_mask);
  sigIntHandler.sa_flags = 0;

  sigaction(SIGINT, &sigIntHandler, NULL);

  int sock;
  if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket");
    exit(1);
  }
  const char *device = opts["device"].as<std::string>().c_str();
  if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, device,
                 strlen(device) + 1) < 0) {
    perror("setsockopt bind device");
    close(sock);
    exit(1);
  }
  /* set the network card in promiscuos mode*/
  // An ioctl() request has encoded in it whether the argument is an in
  // parameter or out parameter SIOCGIFFLAGS	0x8913		/* get flags
  // */ SIOCSIFFLAGS	0x8914		/* set flags			*/

  struct ifreq ethreq;
  strncpy(ethreq.ifr_name, device, IF_NAMESIZE);
  if (ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1) {
    perror("ioctl");
    close(sock);
    exit(1);
  }
  ethreq.ifr_flags |= IFF_PROMISC;
  if (ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1) {
    perror("ioctl");
    close(sock);
    exit(1);
  }

  auto bpf_code = opts["filter"].as<std::string>();
  if (bpf_code.length() > 0) {
    std::istringstream ss(bpf_code);
    int n;
    ss >> n;
    std::cout << n << '\n';

    auto *bpf_code_bin =
        (struct sock_filter *)malloc(sizeof(struct sock_filter) * n);
    for (int i = 0; i < n; ++i) {
      unsigned tjt, tjf;
      ss >> bpf_code_bin[i].code >> tjt >> tjf >> bpf_code_bin[i].k;
      bpf_code_bin[i].jt = tjt;
      bpf_code_bin[i].jf = tjf;

      std::cout << std::format("{} {} {} {}\n", bpf_code_bin[i].code,
                               bpf_code_bin[i].jt, bpf_code_bin[i].jf,
                               bpf_code_bin[i].k);
    }
    struct sock_fprog Filter;
    // error prone code, .len field should be consistent with the real length of
    // the filter code array
    Filter.len = n;
    Filter.filter = bpf_code_bin;

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &Filter,
                   sizeof(Filter)) < 0) {
      perror("setsockopt attach filter");
      close(sock);
      exit(1);
    }
  }

  return sock;
}

void process_ip_payload(unsigned int protocol, uint8_t *buffer) {
  switch (protocol) {
  case 1: {

    if (opts["picmp"].as<bool>() || opts["all"].as<bool>()) {
      print_split("icmp");
      struct icmphdr *icmp_header = (struct icmphdr *)(buffer);

      // 输出 ICMP 类型
      print_table("Type", (unsigned int)icmp_header->type);

      // 输出 ICMP 代码
      print_table("Code", (unsigned int)icmp_header->code);

      // 输出校验和
      print_table("Checksum", ntohs(icmp_header->checksum));
      break;
    }
  }
  case 6: {

    if (opts["ptcp"].as<bool>() || opts["all"].as<bool>()) {
      print_split("tcp");
      struct tcphdr *tcp_header = (struct tcphdr *)(buffer);

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
      break;
    }
  }
  case 17: {
    if (opts["pudp"].as<bool>() || opts["all"].as<bool>()) {
      print_split("udp");
      struct udphdr *udp_header = (struct udphdr *)(buffer);

      // 输出源端口
      print_table("Source Port", ntohs(udp_header->source));

      // 输出目的端口
      print_table("Destination Port", ntohs(udp_header->dest));

      // 输出UDP长度
      print_table("Length", ntohs(udp_header->len));
      break;
    }
  }
  default:
    print_split(std::format("Prorocol number: {0}, I don't know", protocol));
  }
}

void process_frame(uint8_t buffer[]) {

  uint16_t eth_type =
      print_eth((struct ether_header *)buffer, opts["peth"].as<bool>());

  switch (eth_type) {
  case 0x800: {
    auto [protocol, hl] =
        print_ip((struct ip *)(buffer + 14),
                 opts["pip"].as<bool>() || opts["all"].as<bool>());
    process_ip_payload(protocol, buffer + 14 + hl);
    break;
  }
  case 0x806: {
    if (opts["parp"].as<bool>() || opts["all"].as<bool>()) {
      print_split("arp");

      struct arphdr *arp_header =
          (struct arphdr *)(buffer + 14); // ARP 头部紧随以太网头部之后

      // 获取发送者和目标的硬件和协议地址
      unsigned char *sender_hardware_address =
          (unsigned char *)(arp_header + 1);
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
        arp_info = std::format("Request who-has {} tell {}", target_ip,
                               sender_ip, sizeof(struct arphdr));
      } else if (ntohs(arp_header->ar_op) == ARPOP_REPLY) {
        arp_info = std::format("Reply {} is-at "
                               "{}",
                               sender_ip, mac_to_str(sender_hardware_address));
      }

      std::cout << arp_info << std::endl;
    }
    break;
  }
  case 0x86dd:
    auto protocol =
        print_ipv6((struct ip6_hdr *)(buffer + 14),
                   opts["pip"].as<bool>() || opts["all"].as<bool>());
    process_ip_payload(protocol, buffer + 14 + 40);
    break;
  }
}

int main(int argc, char **argv) {
  cxxopts::Options options("my-pcap",
                           "Packet capturing using socket PF_PACKET");
  options.add_options(

      )("e,peth", "Print ethernet info",
        cxxopts::value<bool>()->default_value("false"))(
      "pip", "Print ip info", cxxopts::value<bool>()->default_value("false"))(
      "ptcp", "Print tcp info", cxxopts::value<bool>()->default_value("false"))(
      "pudp", "Print udp info", cxxopts::value<bool>()->default_value("false"))(
      "picmp", "Print icmp info",
      cxxopts::value<bool>()->default_value("false"))(
      "parp", "Print arp info",
      cxxopts::value<bool>()->default_value("false"))("h,help", "Print usage")(
      "filter", "Set bpf", cxxopts::value<std::string>()->default_value(""))(
      "i,device", "Set device",
      cxxopts::value<std::string>()->default_value("eth0"))(
      "a,all", "Print many info",
      cxxopts::value<bool>()->default_value("false"));

  opts = options.parse(argc, argv);

  if (opts.count("help")) {
    std::cout << options.help() << std::endl;
    exit(0);
  }
  int sock = init();

  int n;
  uint8_t buffer[10240];
  // int cnt = 0;

  while (1) {
    n = recvfrom(sock, buffer, 10240, 0, NULL, NULL);
    print_split(std::format("{} bytes read", n));

    if (n < 42) {
      perror("recvfrom():");
      printf("Incomplete packet (errno is %d)\n", errno);
      close(sock);
      exit(0);
    }

    // std::cout << std::format("cont: {}\n", ++cnt);

    process_frame(buffer);
  }
  return 0;
}
