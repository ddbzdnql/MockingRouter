#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sr_utils.h"
#include "sr_protocol.h"

int main(int argc, char ** argv){
  // test out arp_to_buf
  printf("Testing arp_to_buf conversion\n");
  sr_arp_hdr_t * arp = (sr_arp_hdr_t*)malloc(sizeof(sr_arp_hdr_t));

  // create a testing arp struct
  arp->ar_hrd = 12345;
  arp->ar_pro = 54321;
  arp->ar_hln = 111;
  arp->ar_pln = 123;
  arp->ar_op = 13579;
  unsigned char sha[6] = "abcdef";
  memcpy(arp->ar_sha, sha, 6);
  arp->ar_sip = 0x00AABBCC;
  unsigned char tha[6] = "123456";
  memcpy(arp->ar_tha, tha, 6);  
  arp->ar_tip = 0x00ABCDAB;

  // print out info difficult for debugging
  print_addr_eth(arp->ar_sha);
  print_addr_ip_int(arp->ar_sip);
  print_addr_eth(arp->ar_tha);
  print_addr_ip_int(arp->ar_tip);

  // test out arp_to_buf function
  uint8_t * answer = arp_struct_to_buf(arp);
  printf("result of converted header:\n");
  print_hdr_arp(answer);


  // test out buf_to_arp function (based on assumption that previous method is correct.)
  sr_arp_hdr_t * converted = buf_to_arp_struct(answer);
  printf("hrd: %d\n", converted->ar_hrd); 
  printf("pro: %d\n", converted->ar_pro);
  printf("hln: %d\n", converted->ar_hln);
  printf("pln: %d\n", converted->ar_pln);
  printf("opcode: %d\n", converted->ar_op);
  print_addr_eth(converted->ar_sha);
  print_addr_ip_int(converted->ar_sip);
  print_addr_eth(converted->ar_tha);
  print_addr_ip_int(converted->ar_tip);

  // test out ip_to_buf
  printf("Testing ip_to_buf conversion\n");
  sr_ip_hdr_t * ip = (sr_ip_hdr_t *)malloc(sizeof(sr_ip_hdr_t));

  // create a testing ip struct
  ip->ip_hl = 10;
  ip->ip_v = 4;
  ip->ip_tos = 111;
  ip->ip_len = 54321;
  ip->ip_id = 12345;
  ip->ip_off = 0xA040;
  ip->ip_ttl = 123;
  ip->ip_p = 100;
  ip->ip_sum = 13579;
  ip->ip_src = 0x00AABBCCDD;
  ip->ip_dst = 0x00ABCABCAB;
  print_addr_ip_int(ip->ip_src);
  print_addr_ip_int(ip->ip_dst);

  answer = ip_struct_to_buf(ip);
  print_hdr_ip(answer);

  // test out buf_to_ip
  sr_ip_hdr_t * converted_ip = buf_to_ip_struct(answer);
  printf("header len: %d\n", converted_ip->ip_hl);
  printf("version: %d\n", converted_ip->ip_v);
  printf("service: %d\n", converted_ip->ip_tos);
  printf("length: %d\n", converted_ip->ip_len);
  printf("id: %d\n", converted_ip->ip_id);
  printf("offset: %x\n", converted_ip->ip_off);
  printf("time to live: %d\n", converted_ip->ip_ttl);
  printf("protocol: %d\n", converted_ip->ip_p);
  printf("cksum: %d\n", converted_ip->ip_sum);
  print_addr_ip_int(converted_ip->ip_src);
  print_addr_ip_int(converted_ip->ip_dst); 

  // test out icmp_to_buf
  printf("Testing icmp_to_buf conversion\n");
  sr_icmp_t11_hdr_t * icmp = (sr_icmp_t11_hdr_t *)malloc(sizeof(sr_icmp_t11_hdr_t));

  icmp->icmp_type = 123;
  icmp->icmp_code = 9;
  icmp->icmp_sum = 12345;
  icmp->unused = 1234567;
  memcpy(icmp->data, "abcdefghijklmmopqrstuvwxyz0123456789", ICMP_DATA_SIZE);

  answer = icmp_struct_to_buf(icmp);
  print_hdr_icmp(answer);
  printf("Unused: %d\n", ((sr_icmp_t11_hdr_t *)answer)->unused);
  printf("Data: %s\n",  ((sr_icmp_t11_hdr_t *)answer)->data);

  // test out buf_to_icmp
  sr_icmp_t11_hdr_t * converted_icmp = buf_to_icmp_struct(answer);

  printf("cksum: %d\n", converted_icmp->icmp_sum);
  printf("unused: %d\n", converted_icmp->unused);

  // test out ether_to_buf
  printf("Testing out ether_to_buf conversion\n");
  sr_ethernet_hdr_t * ether = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
 
  uint8_t d[ETHER_ADDR_LEN] = {1,2,3,4,5,6};
  uint8_t s[ETHER_ADDR_LEN] = {6,5,4,3,2,1}; 
  memcpy(ether->ether_dhost, d, ETHER_ADDR_LEN);
  memcpy(ether->ether_shost, s, ETHER_ADDR_LEN);
  ether->ether_type = 12345;

  answer = eth_struct_to_buf(ether);
  print_hdr_eth(answer);

  sr_ethernet_hdr_t * converted_ether = buf_to_eth_struct(answer);
  print_addr_eth(converted_ether->ether_dhost);
  print_addr_eth(converted_ether->ether_shost);
  printf("ethertype: %d\n", converted_ether->ether_type); 

  exit(1);
}
