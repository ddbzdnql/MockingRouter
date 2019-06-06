#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "sr_packet.h"
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_rt.h"
#include "sr_arpcache.h"

void sweep_req(struct sr_packet * packet, uint8_t * mac, struct sr_instance * sr){
  if (packet->next){
    sweep_req(packet->next, mac, sr);
    uint8_t * send_buf = packet->buf;
    memcpy(((sr_ethernet_hdr_t *)send_buf)->ether_dhost, mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, send_buf, packet->len, packet->iface);
int * dest_port = (int *)(send_buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+2);
//printf("dest port: %d\n", ntohs(*dest_port));
//free(send_buf); freed in the destroy method so dont bother.
    return;
  }
  uint8_t * send_buf = packet->buf;
  memcpy(((sr_ethernet_hdr_t *)send_buf)->ether_dhost, mac, ETHER_ADDR_LEN);
  sr_send_packet(sr, send_buf, packet->len, packet->iface);
int * dest_port = (int *)(send_buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+2);
//printf("dest port: %d\n", ntohs(*dest_port));
//free(send_buf);
  return;
}

void process_arp_packet(struct sr_instance * sr,
		sr_ethernet_hdr_t * ether,
		sr_arp_hdr_t * arp,
		char * from,
        uint8_t * raw,
        int raw_len){
  if (ether == NULL || arp == NULL){
    return; // so that the program will not break down upon error.
  }
  int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  
  if (arp -> ar_op == ARP_OP_REQUEST){ // request address
    uint32_t req_addr = arp -> ar_tip;

    // store the senders ip address and mac for future reference
    sr_arpcache_insert(&(sr->cache), arp->ar_sha, arp->ar_sip);

    uint8_t * to_send = (uint8_t *)malloc(len);

    struct sr_arpentry * dest_arp = sr_arpcache_lookup(&(sr->cache), req_addr);
    struct sr_if * itf_head = sr->if_list;
    while(itf_head){
      if (ntohl(itf_head->ip) == req_addr){
        break;
      }
      itf_head = itf_head->next;
    }
    if (dest_arp || itf_head){ // know this address, send back
      struct sr_if * src_if = sr_get_interface(sr, from);

      // construct new ethernet and arp packages
      sr_ethernet_hdr_t * send_ether = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
      sr_arp_hdr_t * send_arp = (sr_arp_hdr_t *)malloc(sizeof(sr_arp_hdr_t));
      memcpy(send_ether->ether_dhost, ether->ether_shost, ETHER_ADDR_LEN);
      memcpy(send_ether->ether_shost, src_if->addr, ETHER_ADDR_LEN);
      send_ether->ether_type = ether->ether_type;

      memcpy(send_arp, arp, sizeof(sr_arp_hdr_t));
      send_arp->ar_op = ARP_OP_REPLY;
      if (dest_arp){
        memcpy(send_arp->ar_sha, dest_arp->mac, ETHER_ADDR_LEN);
      }
      else{
        memcpy(send_arp->ar_sha, itf_head->addr, ETHER_ADDR_LEN);
      }
      memcpy(send_arp->ar_tha, arp->ar_sha, ETHER_ADDR_LEN);
      send_arp->ar_sip = arp->ar_tip;
      send_arp->ar_tip = arp->ar_sip;
// stop if you see this sentence
      // fill in the buf
      uint8_t * ether_buf = eth_struct_to_buf(send_ether);
      memcpy(to_send, ether_buf, sizeof(sr_ethernet_hdr_t));
      uint8_t * arp_buf = arp_struct_to_buf(send_arp);
      memcpy(to_send+sizeof(sr_ethernet_hdr_t), arp_buf, sizeof(sr_arp_hdr_t));

      // send and log
      sr_send_packet(sr, to_send, len, from);
free(send_ether);
free(send_arp);
free(ether_buf);
free(arp_buf);
free(to_send);
    }
    else{ // send to longest match of arp dst
      struct sr_rt * rtable = sr_longest_match(sr, arp->ar_tip); /* match method */
      if (!rtable){ // in case doesnt have this dest in rtable
        return;
      }
printf("rtable:\n");
print_addr_ip_int(rtable->dest.s_addr);
      struct sr_if * to_itf = sr_get_interface(sr, rtable->interface);
      memcpy(((sr_ethernet_hdr_t *)raw)->ether_shost, to_itf->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, raw, raw_len, rtable->interface);
free(raw);
    }
  }
  else{ // reply to an arp
    /* insert into the table */
printf("got reply\n");
    sr_arpcache_insert(&(sr->cache), arp->ar_sha, htonl(arp->ar_sip));

pthread_mutex_lock(&(sr->cache.lock));
    struct sr_arpreq * key_req = sr->cache.requests;

    while(key_req){
      if (key_req->ip == arp->ar_sip){
        break;
      }
      key_req = key_req->next;
    }
    if (key_req){
      struct sr_packet * p_head = key_req->packets;
      sweep_req(p_head, arp->ar_sha, sr);
pthread_mutex_unlock(&(sr->cache.lock));
      sr_arpreq_destroy(&(sr->cache), key_req);
pthread_mutex_lock(&(sr->cache.lock));
    }

pthread_mutex_unlock(&(sr->cache.lock));
  }
  
}

/* Populate the new ip header's some generic field from an old one. */
void copy_ip_hdr(sr_ip_hdr_t * from, sr_ip_hdr_t * to){
  to->ip_hl = from->ip_hl;
  to->ip_v = from->ip_v;
  to->ip_tos = from->ip_tos;
  to->ip_id = from->ip_id;
  to->ip_off = from->ip_off;
  to->ip_sum = 0;
}

void process_ip_packet(struct sr_instance * sr,
		uint8_t * raw_ip_buf,
		sr_ethernet_hdr_t * ether,
		sr_ip_hdr_t * ip,
		char * from,
		int len /* length of ip header */){
  if (ether == NULL || ip == NULL){
    return;
  }

  if (len < sizeof(sr_ip_hdr_t)){
    return;
  }

int * dest_port = (int *)(raw_ip_buf + sizeof(sr_ip_hdr_t) + 2);
printf("dest port (treated as UDP packet): %d\n", ntohs(* dest_port));   

  /* checksum */
  uint16_t expected = cksum(raw_ip_buf, sizeof(sr_ip_hdr_t));
  if (expected != 0xffff){
    return;
printf("check sum error! %x\n", expected);
  }

  /* configuration */
  struct sr_if * from_if = sr_get_interface(sr, from);

  sr_ip_hdr_t * send_ip = (sr_ip_hdr_t *)malloc(sizeof(sr_ip_hdr_t));
  copy_ip_hdr(ip, send_ip);

  sr_ethernet_hdr_t * send_ether = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
  send_ether->ether_type = ETYPE_IP;
  /* check destination */
  uint32_t dst_addr = ip->ip_dst;
//print_addr_ip_int(dst_addr);

  struct sr_if * cur = sr->if_list;
  while(cur){
    if (ntohl(cur->ip) == dst_addr){
      break;
    }
    cur = cur->next;
  }

  /* if the packet is for me */
  if (cur != NULL){
    /* configure ether packet here since we're sending back anyway */
    send_ether->ether_type = ETYPE_IP;
    memcpy(send_ether->ether_dhost, ether->ether_shost, ETHER_ADDR_LEN);
    memcpy(send_ether->ether_shost, from_if->addr, ETHER_ADDR_LEN);

    send_ip->ip_ttl = 64;
    send_ip->ip_sum = 0;
    send_ip->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    send_ip->ip_p = IP_PRO_ICMP;

    sr_icmp_hdr_t * icmp;
    sr_icmp_t11_hdr_t * send_icmp = NULL;
    switch(ip->ip_p){
      case IP_PRO_ICMP:
        if (len < sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t)){
          return; // if the payload length not enough for icmp, return
        }
        /* need to configure ip and icmp packet */
        icmp = buf_to_icmp_struct((uint8_t *)raw_ip_buf+sizeof(sr_ip_hdr_t));
        if (icmp->icmp_type == ICMP_TYPE_EREQ){
          int offset = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
printf("%d\n", len-offset);
          send_icmp = (sr_icmp_t11_hdr_t *)malloc(len-sizeof(sr_ip_hdr_t));
          send_icmp->icmp_type = ICMP_TYPE_EREP;
          send_icmp->icmp_code = 0;
          send_icmp->unused = icmp->unused;
          send_icmp->icmp_sum = 0;
 
          send_ip->ip_dst = ip->ip_src;
          send_ip->ip_src = ntohl(cur->ip);
          send_ip->ip_len = len;
         
          uint8_t * send_buf = (uint8_t *)malloc(len+sizeof(sr_ethernet_hdr_t));
          int length = 0;

printf("%d\n", len-offset);
          uint8_t * ether_buf = eth_struct_to_buf(send_ether);
          memcpy(send_buf + length, ether_buf, sizeof(sr_ethernet_hdr_t));

          length += sizeof(sr_ethernet_hdr_t);
          
          uint8_t * ip_buf = ip_struct_to_buf(send_ip);
          ((sr_ip_hdr_t *)ip_buf)->ip_sum = cksum(ip_buf, sizeof(sr_ip_hdr_t));
          memcpy(send_buf + length, ip_buf, sizeof(sr_ip_hdr_t));
          length += sizeof(sr_ip_hdr_t);

          uint8_t * icmp_buf = icmp_struct_to_buf((sr_icmp_hdr_t *)send_icmp);
          //memcpy(icmp_buf + sizeof(sr_icmp_hdr_t), raw_ip_buf+offset, len-offset);
          //((sr_icmp_hdr_t *)icmp_buf)->icmp_sum = cksum(icmp_buf, len-sizeof(sr_ip_hdr_t));
printf("%d\n", len-offset);
          memcpy(send_buf + length, icmp_buf, sizeof(sr_icmp_hdr_t));
          length += sizeof(sr_icmp_hdr_t);

          memcpy(send_buf + length, raw_ip_buf + offset, len-offset);
          sr_icmp_hdr_t * cksum_head = (sr_icmp_hdr_t *)(send_buf + length - sizeof(sr_icmp_hdr_t));          
          cksum_head->icmp_sum = cksum(cksum_head, len-sizeof(sr_ip_hdr_t));

          sr_send_packet(sr, send_buf, len+sizeof(sr_ethernet_hdr_t), from);
free(send_icmp);
free(send_ip);
free(send_ether);
free(send_buf);
free(ether_buf);
free(ip_buf);
free(icmp_buf);
printf("ping reply\n");
          return;
        }
        break;
      case IP_PRO_TCP:
      case IP_PRO_UDP:
        send_icmp = (sr_icmp_t11_hdr_t *)malloc(sizeof(sr_icmp_t11_hdr_t));
        send_icmp->icmp_type = ICMP_TYPE_DEST;
        send_icmp->icmp_code = ICMP_CODE_PORT;
        send_icmp->unused = 0;
        send_icmp->icmp_sum = 0;
 
        memcpy(send_icmp->data, raw_ip_buf, ICMP_DATA_SIZE);

        send_ip->ip_dst = ip->ip_src;
        send_ip->ip_src = ntohl(cur->ip);
      break;
    }

    if (!send_icmp){
      return;
    }
    
    uint8_t * send_buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
    int length = 0;
    uint8_t * ether_buf = eth_struct_to_buf(send_ether);
    memcpy(send_buf + length, ether_buf, sizeof(sr_ethernet_hdr_t));
    length += sizeof(sr_ethernet_hdr_t);

    uint8_t * ip_buf = ip_struct_to_buf(send_ip);
    ((sr_ip_hdr_t *)ip_buf)->ip_sum = cksum(ip_buf, sizeof(sr_ip_hdr_t));
//printf("check sum: %x\n", cksum(ip_buf, sizeof(sr_ip_hdr_t)));
    memcpy(send_buf + length, ip_buf, sizeof(sr_ip_hdr_t));
    length += sizeof(sr_ip_hdr_t);

    uint8_t * icmp_buf = icmp11_struct_to_buf(send_icmp);
    ((sr_icmp_hdr_t *)icmp_buf)->icmp_sum = cksum(icmp_buf, sizeof(sr_icmp_t11_hdr_t));
    memcpy(send_buf + length, icmp_buf, sizeof(sr_icmp_t11_hdr_t));
    length += sizeof(sr_icmp_t11_hdr_t);

    sr_send_packet(sr, send_buf, length, from);
printf("UDP/TCP. replied\n");
free(send_ether);
free(send_ip);
free(send_icmp);
free(send_buf);
free(ether_buf);
free(ip_buf);
free(icmp_buf);
    return;  
  }

  /* if this packet is not for me */
  if (ip->ip_ttl == 1){ // if this packet is expired
    memcpy(send_ether->ether_shost, from_if->addr, ETHER_ADDR_LEN); // send back to where it came form
    memcpy(send_ether->ether_dhost, ether->ether_shost, ETHER_ADDR_LEN);

    /* Handle the ip packet */
    send_ip->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    send_ip->ip_ttl = 64;
    send_ip->ip_sum = 0;
    send_ip->ip_p = IP_PRO_ICMP;
    send_ip->ip_src = ntohl(from_if->ip);
    send_ip->ip_dst = ip->ip_src;

    /* Handle the icmp 11 packet */
    sr_icmp_t11_hdr_t * send_icmp11 = (sr_icmp_t11_hdr_t *)malloc(sizeof(sr_icmp_t11_hdr_t));
    send_icmp11->icmp_type = ICMP_TYPE_TIME;
    send_icmp11->icmp_code = ICMP_CODE_TTL;
    send_icmp11->unused = 0;
    send_icmp11->icmp_sum = 0;

    memcpy(send_icmp11->data, raw_ip_buf, ICMP_DATA_SIZE);

    /* send the buf */
    uint8_t * send_buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
    int length = 0;

    uint8_t * send_ether_buf = eth_struct_to_buf(send_ether);
    memcpy(send_buf + length, send_ether_buf, sizeof(sr_ethernet_hdr_t));
    length += sizeof(sr_ethernet_hdr_t);

    uint8_t * send_ip_buf = ip_struct_to_buf(send_ip);
    ((sr_ip_hdr_t *)send_ip_buf)->ip_sum = cksum(send_ip_buf, sizeof(sr_ip_hdr_t));
    memcpy(send_buf + length, send_ip_buf, sizeof(sr_ip_hdr_t));
    length += sizeof(sr_ip_hdr_t);

    uint8_t * send_icmp_buf = icmp11_struct_to_buf(send_icmp11);
    ((sr_icmp_t11_hdr_t *)send_icmp_buf)->icmp_sum = cksum(send_icmp_buf, sizeof(sr_icmp_t11_hdr_t));
    memcpy(send_buf + length, send_icmp_buf, sizeof(sr_icmp_t11_hdr_t));
    length += sizeof(sr_icmp_t11_hdr_t);

    sr_send_packet(sr, send_buf, length, from);
printf("ttl expired\n");
free(send_ether);
free(send_ip);
free(send_icmp11);
free(send_buf);
free(send_ether_buf);
free(send_ip_buf);
free(send_icmp_buf);
    return;
  }

  /* this packet has not expired(and not for me) */
  uint32_t dest_ip = ip->ip_dst; // in host order
  struct sr_rt * head = sr_longest_match(sr, dest_ip);
  /*while(head){
    if (ntohl(head->dest.s_addr) == dest_ip){ // rtable in network order
      break;
    }
    head = head->next;
  }*/
//printf("head: %p\n", head);
  if (!head){ // destination not in routing table
    memcpy(send_ether->ether_shost, from_if->addr, ETHER_ADDR_LEN);
    memcpy(send_ether->ether_dhost, ether->ether_shost, ETHER_ADDR_LEN);
    send_ether->ether_type = ETYPE_IP;

    /* handle ip packet */
    send_ip->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    send_ip->ip_ttl = 64;
    send_ip->ip_sum = 0;
    send_ip->ip_p = IP_PRO_ICMP;
    send_ip->ip_dst = ip->ip_src;
    send_ip->ip_src = ntohl(from_if->ip);

    /* handle icmp packet */
    sr_icmp_t11_hdr_t * send_icmp = (sr_icmp_t11_hdr_t *)malloc(sizeof(sr_icmp_t11_hdr_t));
    send_icmp->icmp_type = ICMP_TYPE_DEST;
    send_icmp->icmp_code = ICMP_CODE_NET;
    send_icmp->unused = 0;
    send_icmp->icmp_sum = 0;

    memcpy(send_icmp->data, raw_ip_buf, ICMP_DATA_SIZE);

    /* prepare the packet */
    uint8_t * send_buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
    int length = 0;

    uint8_t * send_ether_buf = eth_struct_to_buf(send_ether);
    memcpy(send_buf, send_ether_buf, sizeof(sr_ethernet_hdr_t));
    length += sizeof(sr_ethernet_hdr_t);

    uint8_t * send_ip_buf = ip_struct_to_buf(send_ip);
    ((sr_ip_hdr_t *)send_ip_buf)->ip_sum = cksum(send_ip_buf, sizeof(sr_ip_hdr_t));
    memcpy(send_buf + length, send_ip_buf, sizeof(sr_ip_hdr_t));
    length += sizeof(sr_ip_hdr_t);

    uint8_t * send_icmp_buf = icmp11_struct_to_buf(send_icmp);
    ((sr_icmp_t11_hdr_t *)send_icmp_buf)->icmp_sum = cksum(send_icmp_buf, sizeof(sr_icmp_t11_hdr_t));
    memcpy(send_buf + length, send_icmp_buf, sizeof(sr_icmp_t11_hdr_t));
    length += sizeof(sr_icmp_t11_hdr_t);

    sr_send_packet(sr, send_buf, length, from);
printf("network not in rtable\n");
free(send_ether);
free(send_ip);
free(send_icmp);
free(send_buf);
free(send_ether_buf);
free(send_ip_buf);
free(send_icmp_buf);
    return;
  }

  /* check if we can send it directly */
  struct sr_arpentry * arp_result = sr_arpcache_lookup(&(sr->cache), (head->gw.s_addr));

//printf("arp result: %p\n", arp_result);

  /* prep the packet */
  struct sr_if * to_if = sr_get_interface(sr, head->interface);

  memcpy(send_ether->ether_dhost, ether->ether_shost, ETHER_ADDR_LEN); // if 
  memcpy(send_ether->ether_shost, to_if->addr, ETHER_ADDR_LEN);
  send_ether->ether_type = ETYPE_IP;

  memcpy(send_ip, ip, sizeof(sr_ip_hdr_t));
  send_ip->ip_ttl -= 1;
  send_ip->ip_sum = 0;

  uint8_t * send_buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + len);
  int length = 0;

  uint8_t * send_ether_buf = eth_struct_to_buf(send_ether);
  memcpy(send_buf + length, send_ether_buf, sizeof(sr_ethernet_hdr_t));
  length += sizeof(sr_ethernet_hdr_t);

  uint8_t * send_ip_buf = ip_struct_to_buf(send_ip);
  ((sr_ip_hdr_t*)send_ip_buf)->ip_sum = cksum(send_ip_buf, sizeof(sr_ip_hdr_t));
  memcpy(send_buf + length, send_ip_buf, sizeof(sr_ip_hdr_t));
  length += sizeof(sr_ip_hdr_t);

  memcpy(send_buf + length, raw_ip_buf+sizeof(sr_ip_hdr_t), len-sizeof(sr_ip_hdr_t));
  length += len - sizeof(sr_ip_hdr_t);


  if (!arp_result){ // doesn't have arp entry
    time_t cur_time;

    uint32_t dest_gw = ntohl(head->gw.s_addr);
 
 
    /* queue up the packet */
    sr_arpcache_queuereq(&(sr->cache), dest_gw, send_buf, len + sizeof(sr_ethernet_hdr_t), to_if->name);

printf("cached in arp for arp reply\n");
free(send_ether);
free(send_ip);
free(send_ether_buf);
free(send_ip_buf);

    return;
  }
 
  /* can send if directly */
  memcpy(((sr_ethernet_hdr_t *)send_buf)->ether_dhost, arp_result->mac, ETHER_ADDR_LEN);
  sr_send_packet(sr, send_buf, length, to_if->name);
printf("sent directly: %d\n", length);
//print_hdrs(send_buf, len+sizeof(sr_ethernet_hdr_t));
free(send_ether);
free(send_ip);
free(send_buf);
free(send_ether_buf);
free(send_ip_buf);
  
}
