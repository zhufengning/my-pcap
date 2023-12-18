#include <arpa/inet.h>
#include <format>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

std::string mac_to_str(uint8_t *addr) {
  return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", addr[0],
                     addr[1], addr[2], addr[3], addr[4], addr[5]);
}