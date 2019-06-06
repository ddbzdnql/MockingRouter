#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
pthread_mutex_lock(&(sr->cache.lock)); 
  struct sr_arpreq * sr_reqs = sr->cache.requests;
  while(sr_reqs){
    if (sr_reqs->times_sent >= 5){
printf("expired arp request\n");
      /* send ICMP back and sweep the packets */
      struct sr_packet * cur_pac = sr_reqs->packets;
      while(cur_pac){
        sr_ethernet_hdr_t * send_ether = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
        sr_ip_hdr_t * send_ip = (sr_ip_hdr_t *)malloc(sizeof(sr_ip_hdr_t));
        sr_icmp_hdr_t * send_icmp = (sr_icmp_hdr_t *)malloc(sizeof(sr_icmp_hdr_t));

        uint8_t * raw_buf = cur_pac->buf;
        int length = 0;
        sr_ethernet_hdr_t * in_ether = buf_to_eth_struct(raw_buf+length);
        length += sizeof(sr_ethernet_hdr_t);
        /* look for the way back(itf and mac) */
/*
        struct sr_if * if_head = sr->if_list;
        while(if_head){
print_addr_eth(if_head->addr);
          if (strncmp((char *)(if_head->addr), (char *)(in_ether->ether_dhost), ETHER_ADDR_LEN) == 0){
            break; // this is the mac and itf to send back 
          }
          if_head = if_head->next;
        }
*/
        memcpy(send_ether->ether_dhost, in_ether->ether_dhost, ETHER_ADDR_LEN);

        sr_ip_hdr_t * in_ip = buf_to_ip_struct(raw_buf+length);
        length += sizeof(sr_ip_hdr_t);
        uint32_t ip_src = in_ip->ip_src;
print_addr_ip_int(ip_src);
        struct sr_rt * rtable = sr_longest_match(sr, ip_src);
/*
        while(rtable){ // TODO replace with a longest match method 
          if(rtable->gw.s_addr == ip_src){
            break;
          }
          rtable = rtable->next;
        }
*/
        if (!rtable){
          cur_pac = cur_pac->next;
          continue;
        }
        struct sr_if * dst_itf = sr_get_interface(sr, rtable->interface);
        memcpy(send_ether->ether_shost, dst_itf->addr, ETHER_ADDR_LEN);

        /* TODO the regular procedure */
        send_ether->ether_type = ETYPE_IP;

        send_ip->ip_hl = in_ip->ip_hl;
        send_ip->ip_v = in_ip->ip_v;
        send_ip->ip_tos = 0;
        send_ip->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
        send_ip->ip_off = in_ip->ip_off;
        send_ip->ip_ttl = 64;
        send_ip->ip_p = IP_PRO_ICMP;
        send_ip->ip_sum = 0;
        send_ip->ip_src = ntohl(dst_itf->ip);
        send_ip->ip_dst = in_ip->ip_src;

        send_icmp->icmp_type = ICMP_TYPE_DEST;
        send_icmp->icmp_code = ICMP_CODE_HOST; /* TODO add this in protocol */
        send_icmp->icmp_sum = 0;
        send_icmp->unused = 0;     

        uint8_t * send_buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
        length = 0;
        memcpy(send_buf+length, eth_struct_to_buf(send_ether), sizeof(sr_ethernet_hdr_t));
        length += sizeof(sr_ethernet_hdr_t);

        uint8_t * send_ip_buf = ip_struct_to_buf(send_ip);
        ((sr_ip_hdr_t *)send_ip_buf)->ip_sum = cksum(send_ip_buf, sizeof(sr_ip_hdr_t));
        memcpy(send_buf+length, send_ip_buf, sizeof(sr_ip_hdr_t));
        length += sizeof(sr_ip_hdr_t);

        uint8_t * send_icmp_buf = icmp_struct_to_buf(send_icmp);
        ((sr_icmp_hdr_t *)send_icmp_buf)->icmp_sum = cksum(send_icmp_buf, sizeof(sr_icmp_hdr_t));
        memcpy(send_buf+length, send_icmp_buf, sizeof(sr_icmp_hdr_t));
        length += sizeof(sr_icmp_hdr_t);

        sr_send_packet(sr, send_buf, length, dst_itf->name);
print_hdrs(send_buf, length);
        /* TODO free all packets */
        cur_pac = cur_pac->next;
      }
      struct sr_arpreq * to_destroy = sr_reqs;
      sr_reqs = sr_reqs->next;
pthread_mutex_unlock(&(sr->cache.lock));
      sr_arpreq_destroy(&(sr->cache), to_destroy);
pthread_mutex_lock(&(sr->cache.lock));
      continue;
    }
    time(&(sr_reqs->sent));
    sr_reqs->times_sent += 1;
     
    sr_ethernet_hdr_t * send_ether = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
    sr_arp_hdr_t * send_arp = (sr_arp_hdr_t *)malloc(sizeof(sr_arp_hdr_t));

    uint32_t needle = sr_reqs->ip;
    struct sr_rt * rtable = sr_longest_match(sr, needle);
/*
    while(rtable){
      if (needle == ntohl(rtable->gw.s_addr)){
        break;
      }
      rtable = rtable->next;
    }
*/
    struct sr_if * to_if = sr_get_interface(sr, rtable->interface);
    
    uint8_t broadcast[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(send_ether->ether_dhost, broadcast, ETHER_ADDR_LEN);
    memcpy(send_ether->ether_shost, to_if->addr, ETHER_ADDR_LEN);
    send_ether->ether_type = ETYPE_ARP;

    send_arp->ar_hrd = ARP_HRD_ETH;
    send_arp->ar_pro = ETYPE_IP;
    send_arp->ar_hln = 6;
    send_arp->ar_pln = 4;
    send_arp->ar_op = ARP_OP_REQUEST;
    memcpy(send_arp->ar_sha, to_if->addr, ETHER_ADDR_LEN);
    send_arp->ar_sip = ntohl(to_if->ip);
    send_arp->ar_tip = ntohl(rtable->gw.s_addr);

    uint8_t * send_buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    int length = 0;
    memcpy(send_buf + length, eth_struct_to_buf(send_ether), sizeof(sr_ethernet_hdr_t));
    length += sizeof(sr_ethernet_hdr_t);

    memcpy(send_buf + length, arp_struct_to_buf(send_arp), sizeof(sr_arp_hdr_t));
    length += sizeof(sr_arp_hdr_t);

    sr_send_packet(sr, send_buf, length, to_if->name); 
    
    /* TODO free */

    sr_reqs = sr_reqs->next;
  }
pthread_mutex_unlock(&(sr->cache.lock));
//printf("finished\n");
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

