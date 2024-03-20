#include "addr_conv.hpp"
#include "counter.hpp"
#include "cxxopts.hpp"
#include "output.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <ctime>
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

struct PacketCounter global_counter = {0};

std::unordered_set<std::string> global_mac_list;

void print_hex(unsigned char *buffer, int n) {
  int i;
  for (i = 0; i < n; i++) {
    // 每16个字节打印一行
    if (i % 16 == 0)
      printf("%08x: ", i);

    // 打印一个字节的十六进制值
    printf("%02x ", (unsigned char)buffer[i]);

    // 每两个字节后，添加一个空格，如同xxd工具
    if ((i + 1) % 2 == 0)
      printf(" ");

    // 每16个字节或者在结束处显示ASCII字符
    if ((i + 1) % 16 == 0 || i == n - 1) {
      int j;
      // 结束处可能不够16个字节，用空格填充
      while ((i + 1) % 16 != 0) {
        printf("   ");
        i++;
      }
      printf(" ");

      // 打印ASCII字符表示，非打印字符替换为'.'
      for (j = i - 15; j <= i; j++) {
        putchar(isprint(buffer[j]) ? buffer[j] : '.');
      }
      printf("\n");
    }
  }
}

void my_handler(int s) {
  printf("Caught signal %d\n", s);
  for (auto v : global_mac_list) {
    std::cout << v << std::endl;
  }
  global_counter.end_time = std::time(nullptr);
  print_split("Summary");
  print_table("All", global_counter.all);
  print_table("Start time",
              std::asctime(std::localtime(&global_counter.start_time)));
  print_table("End time",
              std::asctime(std::localtime(&global_counter.end_time)));
  auto duration = global_counter.end_time - global_counter.start_time;
  print_table("Duration(sec)", duration);
  print_table("Total eth packets", global_counter.all);
  print_table("Eth runt frames", global_counter.eth_runt_frame);
  print_table("Eth jumbo", global_counter.eth_jumbo_frame);
  print_table("Total bytes", global_counter.bytes);
  print_table("Speed(byte/sec)", global_counter.bytes / duration);
  print_table("Packet speed(packet/sec)", global_counter.all / duration);
  print_table("Total arp packets", global_counter.arp);
  print_table("Total ip packets", global_counter.ip);
  print_table("Total ip bytes", global_counter.ip_bytes);
  print_table("Total ipv4 boardcast packets", global_counter.ipv4_boardcast);
  print_table("Total ip6 packets", global_counter.ip6);
  print_table("Total udp packets", global_counter.udp);
  print_table("Total tcp packets", global_counter.tcp);
  print_table("Total icmp packets", global_counter.icmp);
  print_table("Total icmp redirect packets", global_counter.icmp_redirect);
  print_table("Total icmp destination unreach packets",
              global_counter.icmp_destination_unreach);

  exit(1);
}

int init() {
  global_counter.start_time = std::time(nullptr);

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

      // std::cout << std::format("{} {} {} {}\n", bpf_code_bin[i].code,
      //                          bpf_code_bin[i].jt, bpf_code_bin[i].jf,
      //                          bpf_code_bin[i].k);
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
    global_counter.icmp++;
    if (opts["picmp"].as<bool>() || opts["all"].as<bool>()) {
      struct icmphdr *icmp_header = (struct icmphdr *)(buffer);
      if (icmp_header->type == ICMP_REDIRECT) {
        global_counter.icmp_redirect++;
      } else if (icmp_header->type == ICMP_DEST_UNREACH) {
        global_counter.icmp_destination_unreach++;
      }
      print_icmp(icmp_header);
      break;
    }
  }
  case 6: {
    global_counter.tcp++;
    if (opts["ptcp"].as<bool>() || opts["all"].as<bool>()) {
      struct tcphdr *tcp_header = (struct tcphdr *)(buffer);

      print_tcp(tcp_header);
      break;
    }
  }
  case 17: {
    global_counter.udp++;
    if (opts["pudp"].as<bool>() || opts["all"].as<bool>()) {
      struct udphdr *udp_header = (struct udphdr *)(buffer);
      print_udp(udp_header);
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
    global_counter.ip++;
    auto [protocol, hl] =
        print_ip((struct ip *)(buffer + 14),
                 opts["pip"].as<bool>() || opts["all"].as<bool>());
    process_ip_payload(protocol, buffer + 14 + hl);
    break;
  }
  case 0x806: {
    global_counter.arp++;
    if (opts["parp"].as<bool>() || opts["all"].as<bool>()) {

      struct arphdr *arp_header =
          (struct arphdr *)(buffer + 14); // ARP 头部紧随以太网头部之后

      print_arp(arp_header);
    }
    break;
  }
  case 0x86dd:
    global_counter.ip6++;
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
      cxxopts::value<bool>()->default_value("false"))(
      "full", "Print hex of packet",
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
    global_counter.all++;
    global_counter.bytes += n;
    // Detect jumbo frames and runt frames
    if (n > ETH_FRAME_LEN) {
      global_counter.eth_jumbo_frame++;
    } else if (n < 64) {
      global_counter.eth_runt_frame++;
    }

    // std::cout << std::format("cont: {}\n", ++cnt);

    process_frame(buffer);

    if (opts["full"].as<bool>()) {
      print_hex(buffer, n);
    }
  }
  return 0;
}
