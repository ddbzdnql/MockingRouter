/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_packet.h"

#define IPV4 0x0800
#define ARP 0x0806

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

struct sr_rt * ip_match(struct sr_instance * sr, uint32_t key){
  struct sr_rt * result = NULL;
  struct sr_rt * cur = sr->routing_table;
  int max_match = 1<<31;
  while(cur){
    uint32_t cur_d = cur->dest.s_addr;
    uint32_t cur_m = cur->mask.s_addr;
    if (((cur_d&cur_m)^(key&cur_m)) == 0){ // this entry is a match
      if (cur_m > max_match){ // but still needs to check if its longest match
        max_match = cur_m;
        result = cur;
      }
    }
    cur = cur->next;
  }
  return result;
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);


//printf("*** -> Received packet of length %d \n",len);
//print_hdrs(packet, len);
  int cursor = 0, next = sizeof(sr_ethernet_hdr_t);
  if (len < cursor+next){
    return;
  }

  sr_ethernet_hdr_t * ether = buf_to_eth_struct(packet+cursor);
  cursor += next;
 
 
  if (ether->ether_type == ETYPE_ARP){
    next = sizeof(sr_arp_hdr_t);
    if (len < cursor+next){
      return;
    }
    sr_arp_hdr_t * arp = buf_to_arp_struct(packet + cursor); 
    cursor += next;
    
    process_arp_packet(sr, ether, arp, interface, packet, len);

  }else{
    if(ether->ether_type == ETYPE_IP){
      next = sizeof(sr_ip_hdr_t);
      if (len < cursor+next){
        return;
      }
printf("\nreceived ip packet\n");
      sr_ip_hdr_t * ip = buf_to_ip_struct(packet + cursor);
      process_ip_packet(sr, packet+cursor, ether, ip, interface, len-cursor); 
      cursor += next;

      
    }
    else{
      return;
    }
  }

  /* fill in code here */

}/* end sr_ForwardPacket */

