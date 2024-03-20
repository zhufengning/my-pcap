#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Pseudo header needed for TCP header checksum calculation
struct pseudo_header {
  uint32_t source_address;
  uint32_t dest_address;
  uint8_t placeholder;
  uint8_t protocol;
  uint16_t tcp_length;
};

// Generic checksum calculation function
unsigned short checksum(void *b, int len) {
  unsigned short *buf = b;
  unsigned int sum = 0;
  unsigned short result;

  for (sum = 0; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
    sum += *(unsigned char *)buf;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

int main() {
  int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock < 0) {
    perror("socket");
    return -1;
  }

  // Data to represent the TCP/IP packet
  char datagram[4096];
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
  struct sockaddr_in sin;
  struct pseudo_header psh;
  const char *target_ip = "192.168.1.2"; // Destination IP address
  const char *fake_src_ip = "10.0.2.15"; // Fake source IP address

  sin.sin_family = AF_INET;
  sin.sin_port = htons(80);
  sin.sin_addr.s_addr = inet_addr(target_ip);

  memset(datagram, 0, 4096); // Zero out the buffer

  // Fill in the IP Header
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
  iph->id = htonl(54321); // Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;                      // Set to 0 before calculating checksum
  iph->saddr = inet_addr(fake_src_ip); // Spoof the source IP address
  iph->daddr = sin.sin_addr.s_addr;

  // TCP Header
  tcph->source = htons(12345); // Source port number
  tcph->dest = htons(80);      // Destination port number
  tcph->seq = 0;
  tcph->ack_seq = 0;
  tcph->doff = 5; // TCP header size
  tcph->fin = 0;
  tcph->syn = 1; // SYN flag
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->window = htons(5840); // Maximum allowed window size
  tcph->check = 0;            // Set to 0 before calculating checksum
  tcph->urg_ptr = 0;

  // Now the IP checksum
  iph->check = checksum((unsigned short *)datagram, iph->tot_len);

  // TCP checksum
  psh.source_address = inet_addr(fake_src_ip);
  psh.dest_address = sin.sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr));

  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
  char *pseudogram = malloc(psize);

  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr));

  tcph->check = checksum((unsigned short *)pseudogram, psize);

  // Inform the kernel not to fill up the packet structure. We'll build it
  // on our own.
  int one = 1;
  const int *val = &one;
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
    perror("setsockopt");
    return -1;
  }

  // Send the packet
  if (sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
             sizeof(sin)) < 0) {
    perror("sendto failed");
  } else {
    printf("Packet Sent\n");
  }

  // Data sent. Close the socket.
  close(sock);
  return 0;
}