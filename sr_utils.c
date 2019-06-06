#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += 4;
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#define OCTET 8
#define OCTET_MASK 255

#define ARP_FIX_LENGTH 16 + ETHER_ADDR_LEN*2
#define ARP_OS_HRD 0
#define ARP_OS_PRO 2
#define ARP_OS_HLN 4
#define ARP_OS_PLN 5
#define ARP_OS_OP  6
#define ARP_OS_SHA 8
#define ARP_OS_SIP 8 + ETHER_ADDR_LEN
#define ARP_OS_THA 12 + ETHER_ADDR_LEN
#define ARP_OS_TIP 12 + ETHER_ADDR_LEN*2

uint8_t * arp_struct_to_buf(sr_arp_hdr_t * arp){
  int length = sizeof(sr_arp_hdr_t);
  uint8_t * buf = (uint8_t *)malloc(length);

  int i;
 
  //zero out buf
  for (i=0; i<length; i++){
    buf[i] = 0;
  }

  uint8_t mask = OCTET_MASK;
  //handle hrd
  unsigned short raw_hrd = arp->ar_hrd;
  //raw_hrd = htons(raw_hrd);
  buf[ARP_OS_HRD] = (raw_hrd >> OCTET) & mask;
  buf[ARP_OS_HRD+1] = raw_hrd & mask;

  //handle pro
  unsigned short raw_pro = arp->ar_pro;
  //raw_pro = htons(raw_pro);
  buf[ARP_OS_PRO] = (raw_pro >> OCTET) & mask;
  buf[ARP_OS_PRO+1] = raw_pro & mask;

  //handle hln
  uint8_t raw_hln = arp->ar_hln;
  buf[ARP_OS_HLN] = raw_hln;

  //handle pln
  uint8_t raw_pln = arp->ar_pln;
  buf[ARP_OS_PLN] = raw_pln;

  //handle op
  unsigned short raw_op = arp->ar_op;
  //raw_op = htons(raw_op);
  buf[ARP_OS_OP] = (raw_op >> OCTET) & mask;
  buf[ARP_OS_OP+1] = raw_op & mask;

  //handle sha
  unsigned char * raw_sha = (arp->ar_sha); //no need for htonl since it is address
  for (i=0; i<ETHER_ADDR_LEN; i++){
    buf[ARP_OS_SHA+i] = raw_sha[i];
  }

  //handle sip
  uint32_t raw_sip = (uint32_t)(arp->ar_sip);
  //raw_sip = htonl(raw_sip);
  for (i=3; i>=0; i--){
    buf[ARP_OS_SIP+(3-i)] = (raw_sip >> (i*OCTET)) & mask;
  }

  //handle tha
  unsigned char * raw_tha = (arp->ar_tha);
  for (i=0; i<ETHER_ADDR_LEN; i++){
    buf[ARP_OS_THA+i] = raw_tha[i];
  }

  //handle tip
  uint32_t raw_tip = (uint32_t)(arp->ar_tip);
  //raw_tip = htonl(raw_tip);
  for (i=3; i>=0; i--){
    buf[ARP_OS_TIP+(3-i)] = (raw_tip >> (i*OCTET)) & mask;
  }
  
  return buf;
}

sr_arp_hdr_t * buf_to_arp_struct(uint8_t * buf){
  sr_arp_hdr_t * arp = (sr_arp_hdr_t *)malloc(sizeof(sr_arp_hdr_t));
  sr_arp_hdr_t * raw = (sr_arp_hdr_t *)buf;
  arp->ar_hrd = ntohs(raw->ar_hrd);
  arp->ar_pro = ntohs(raw->ar_pro);
  arp->ar_hln = raw->ar_hln;
  arp->ar_pln = raw->ar_pln;
  arp->ar_op = ntohs(raw->ar_op);
  arp->ar_sip = ntohl(raw->ar_sip);
  arp->ar_tip = ntohl(raw->ar_tip);
  int i;
  for (i=0; i<ETHER_ADDR_LEN; i++){
    arp->ar_sha[i] = raw->ar_sha[i];
    arp->ar_tha[i] = raw->ar_tha[i];
  }
  return arp; 
}

#define IP_OS_HLV 0
#define IP_OS_TOS 1
#define IP_OS_LEN 2
#define IP_OS_ID 4
#define IP_OS_OFF 6
#define IP_OS_TTL 8
#define IP_OS_P 9
#define IP_OS_SUM 10
#define IP_OS_SRC 12
#define IP_OS_DST 16

uint8_t * ip_struct_to_buf(sr_ip_hdr_t * ip){
  uint8_t * buf = (uint8_t *)malloc(sizeof(sr_ip_hdr_t));

  uint8_t mask = OCTET_MASK;
  int i;

  // handle first two fields depending on endians
  if (__BYTE_ORDER == __LITTLE_ENDIAN){
    buf[IP_OS_HLV] = (ip->ip_v << 4) + ip->ip_hl;
  }
  else{
    buf[IP_OS_HLV] = (ip->ip_hl << 4) + ip->ip_v;
  }

  // handle tos
  buf[IP_OS_TOS] = ip->ip_tos;
  
  // handle len
  buf[IP_OS_LEN] = (ip->ip_len >> OCTET) & mask;
  buf[IP_OS_LEN+1] = ip->ip_len & mask;

  // handle id
  buf[IP_OS_ID] = (ip->ip_id >> OCTET) & mask;
  buf[IP_OS_ID+1] = ip->ip_id & mask;

  // handle offset
  buf[IP_OS_OFF] = (ip->ip_off >> OCTET) & mask;
  buf[IP_OS_OFF+1] = ip->ip_off & mask;

  // handle ttl
  buf[IP_OS_TTL] = ip->ip_ttl;

  // handle protocol
  buf[IP_OS_P] = ip->ip_p;

  // handle sum
  uint16_t temp_sum = (ip->ip_sum);
  buf[IP_OS_SUM] = (temp_sum >> OCTET) & mask;
  buf[IP_OS_SUM+1] = temp_sum & mask;

  // handle src, dst
  for (i=3; i>=0; i--){
    buf[IP_OS_SRC+(3-i)] = (ip->ip_src >> (i*OCTET)) & mask;
    buf[IP_OS_DST+(3-i)] = (ip->ip_dst >> (i*OCTET)) & mask;
  }

  return buf;
}

sr_ip_hdr_t * buf_to_ip_struct(uint8_t * buf){
  sr_ip_hdr_t * raw = (sr_ip_hdr_t *)buf;
  sr_ip_hdr_t * hdr = (sr_ip_hdr_t *)malloc(sizeof(sr_ip_hdr_t));

  hdr->ip_hl = raw->ip_hl;
  hdr->ip_v = raw->ip_v;

  hdr->ip_tos = raw->ip_tos;
  hdr->ip_len = ntohs(raw->ip_len);
  hdr->ip_id = ntohs(raw->ip_id);
  hdr->ip_off = ntohs(raw->ip_off);

  hdr->ip_ttl = raw->ip_ttl;
  hdr->ip_p = raw->ip_p;
  hdr->ip_sum = raw->ip_sum;
  hdr->ip_src = ntohl(raw->ip_src);
  hdr->ip_dst = ntohl(raw->ip_dst);

  return hdr;
}

#define ICMP_OS_TYPE 0
#define ICMP_OS_CODE 1
#define ICMP_OS_SUM 2
#define ICMP_OS_UN 4
#define ICMP_OS_DATA 8
uint8_t * icmp11_struct_to_buf(sr_icmp_t11_hdr_t * icmp){
  uint8_t * buf = (uint8_t *)malloc(sizeof(sr_icmp_t11_hdr_t));

  uint8_t mask = OCTET_MASK;  

  buf[ICMP_OS_TYPE] = icmp->icmp_type;

  buf[ICMP_OS_CODE] = icmp->icmp_code;

  uint16_t sum = (icmp->icmp_sum);
  buf[ICMP_OS_SUM] = (sum >> OCTET) & mask;
  buf[ICMP_OS_SUM+1] = sum & mask;

  uint32_t unused = (icmp->unused);
  ((sr_icmp_t11_hdr_t *)buf)->unused = (icmp->unused);

  memcpy(buf+ICMP_OS_DATA, icmp->data, ICMP_DATA_SIZE);

  return buf;
}

sr_icmp_t11_hdr_t * buf_to_icmp11_struct(uint8_t * buf){
  sr_icmp_t11_hdr_t * raw = (sr_icmp_t11_hdr_t *)buf;
  sr_icmp_t11_hdr_t * icmp = (sr_icmp_t11_hdr_t *)malloc(sizeof(sr_icmp_t11_hdr_t));

  memcpy(icmp, raw, sizeof(sr_icmp_t11_hdr_t));

  return icmp;
}

uint8_t * icmp_struct_to_buf(sr_icmp_hdr_t * icmp){
  uint8_t * buf = (uint8_t *)malloc(sizeof(sr_icmp_t11_hdr_t));

  uint8_t mask = OCTET_MASK;  
  int i;

  buf[ICMP_OS_TYPE] = icmp->icmp_type;

  buf[ICMP_OS_CODE] = icmp->icmp_code;

  uint16_t sum = (icmp->icmp_sum);
  buf[ICMP_OS_SUM] = (sum >> OCTET) & mask;
  buf[ICMP_OS_SUM+1] = sum & mask;

  ((sr_icmp_hdr_t *)buf)->unused = (icmp->unused);
    

  return buf;
}

sr_icmp_hdr_t * buf_to_icmp_struct(uint8_t * buf){
  sr_icmp_hdr_t * raw = (sr_icmp_hdr_t *)buf;
  sr_icmp_hdr_t * icmp = (sr_icmp_hdr_t *)malloc(sizeof(sr_icmp_hdr_t));

  memcpy(icmp, raw, sizeof(sr_icmp_hdr_t));

  return icmp;

}

uint8_t * eth_struct_to_buf(sr_ethernet_hdr_t * ether){
  uint8_t * buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t));
  memcpy(buf, ether->ether_dhost, ETHER_ADDR_LEN);
  memcpy(buf + ETHER_ADDR_LEN, ether->ether_shost, ETHER_ADDR_LEN);
  
  uint16_t type = (ether->ether_type);
  uint8_t mask = OCTET_MASK;

  buf[ETHER_ADDR_LEN*2] = (type >> OCTET) & mask;
  buf[ETHER_ADDR_LEN*2+1] = type & mask;

  //memcpy(buf, ether, sizeof(sr_ethernet_hdr_t));
 
  return buf;
}

sr_ethernet_hdr_t * buf_to_eth_struct(uint8_t * buf){
  sr_ethernet_hdr_t * raw = (sr_ethernet_hdr_t *)buf;
  sr_ethernet_hdr_t * ether = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
  memcpy(ether->ether_dhost, raw->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ether->ether_shost, raw->ether_shost, ETHER_ADDR_LEN);
  ether->ether_type = ntohs(raw->ether_type);
  return ether;
}

struct sr_rt * sr_longest_match(struct sr_instance * sr, uint32_t ip){
//printf("looking for: \n");
//print_addr_ip_int(ip);
  struct sr_rt * t_head = sr->routing_table;
  uint32_t long_mask = 0;
  struct sr_rt * toRet = NULL;
  ip = htonl(ip);
  while(t_head){
    uint32_t cur_mask = t_head->mask.s_addr;
    uint32_t cur_dst = t_head->dest.s_addr;
    if (!((ip&cur_mask)^(cur_dst&cur_mask))){
      if (toRet == NULL || long_mask < cur_mask){
        toRet = t_head;
        long_mask = cur_mask;
      }
    }
    t_head = t_head->next;
  }
  return toRet;
}
