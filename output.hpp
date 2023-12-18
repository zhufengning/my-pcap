#include "addr_conv.hpp"
#include <arpa/inet.h>
#include <iomanip>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>
void print_line();
void print_split(std::string s);
// 针对整数类型的重载
template <typename T1, typename T2>
typename std::enable_if<std::is_integral<T2>::value, void>::type
print_table(T1 t1, T2 t2) {
  std::cout << std::left << std::setw(25) << t1 << "\t0x" << std::hex << t2
            << std::dec << "(" << t2 << ")"
            << std::endl; // 切换到 16 进制输出，然后回到 10 进制
}

template <typename T1, typename T2>
typename std::enable_if<!std::is_integral<T2>::value, void>::type
print_table(T1 t1, T2 t2) {
  std::cout << std::left << std::setw(25) << t1 << "\t" << t2 << std::endl;
}
uint16_t print_eth(struct ether_header *ethhead, bool prt);
std::tuple<uint8_t, unsigned int> print_ip(struct ip *iphead, bool prt);
uint8_t print_ipv6(struct ip6_hdr *iphead, bool prt);