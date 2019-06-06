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
print_addr_ip_int(dst_addr);

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
    send_eth->ether_type = ETYPE_IP;
    memcpy(send_ether->ether_dst, ether->ether_src, ETHER_ADDR_LEN);
    memcpy(send_ether->ether_src, from_if->addr, ETHER_ADDR_LEN);
    sr_icmp_hdr_t * icmp, * send_icmp = NULL;
    switch(ip->ip_p){
      case IP_PRO_ICMP:
        if (len < sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t)){
          return; // if the payload length not enough for icmp, return
        }
        /* need to configure ip and icmp packet */
        icmp = buf_to_icmp_struct((uint8_t *)raw_ip_buf+sizeof(sr_ip_hdr_t));
        if (icmp->icmp_type == ICMP_TYPE_EREQ){
          send_icmp = (sr_icmp_hdr_t *)malloc(sizeof(sr_icmp_hdr_t));
          send_icmp->icmp_type = ICMP_TYPE_EREP;
          send_icmp->icmp_code = 0;
          send_icmp->unused = icmp->unused;
          send_icmp->icmp_sum = 0;
        
          send_ip->ip_dst = ip->ip_src;
          send_ip->ip_src = ntohl(cur->ip);
        }
        break;
      case IP_PRO_TCP:
      case IP_PRO_UDP:
        send_icmp = (sr_icmp_hdr_t *)malloc(sizeof(sr_icmp_hdr_t));
        send_icmp->icmp_type = ICMP_TYPE_DEST;
        send_icmp->icmp_code = ICMP_CODE_PORT;
        send_icmp->unused = 0;
        send_icmp->icmp_sum = 0;

        send_ip->ip_dst = ip->ip_src;
        send_ip->ip_src = ntohl(from_if->ip);
      break;
    }

    if (!send_icmp){
      return;
    }
    
    uint8_t * send_buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    int length = 0;
    memcpy(send_buf + length, eth_struct_to_buf(send_ether), sizeof(sr_ethernet_hdr_t));
    length += sizeof(st_ethernet_hdr_t);

    uint8_t * ip_buf = ip_struct_to_buf(send_ip);
    ((sr_ip_hdr_t *)ip_buf)->ip_sum = cksum(ip_buf, sizeof(sr_ip_hdr_t));
    memcpy(send_buf + length, ip_struct_to_buf(ip_buf), sizeof(sr_ip_hdr_t));
    length += sizeof(sr_ip_hdr_t);

    uint8_t * icmp_buf = icmp_struct_to_buf(send_icmp);
    ((sr_icmp_hdr_t *)icmp_buf)->icmp_sum = cksum(icmp_buf, sizeof(sr_icmp_hdr_t));
    memcpy(send_buf + length, icmp_buf, sizeof(sr_icmp_hdr_t));
    length += sizeof(sr_icmp_hdr_t);

    sr_send_packet(sr, send_buf, length, from);

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
    send_ip->ip_p = IP_PRO_ICMP
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

    memcpy(send_buf + length, eth_struct_to_buf(send_ether), sizeof(sr_ethernet_hdr_t));
    length += sizeof(sr_ethernet_hdr_t);

    uint8_t * send_ip_buf = ip_struct_to_buf(send_ip);
    ((sr_ip_hdr_t *)send_ip_buf)->ip_sum = cksum(send_ip_buf, sizeof(sr_ip_hdr_t));
    memcpy(send_buf + length, send_ip_buf, sizeof(sr_ip_hdr_t));
    length += sizeof(sr_ip_hdr_t);

    uint8_t * send_icmp_buf = icmp11_struct_to_buf(send_icmp11);
    ((sr_icmp_t11_hdr_t *)send_icmp_buf)->icmp_sum = cksum(send_icmp11_buf, sizeof(sr_icmp_t11_hdr_t));
    memcpy(send_buf + length, send_icmp_buf, sizeof(sr_icmp_t11_hdr_t));
    length += sizeof(sr_icmp_t11_hdr_t);

    sr_send_packet(sr, send_buf, length, from);

    return;
  }

  /* this packet has not expired(and not for me) */
  uint32_t dest_ip = ip->ip_dst; // in host order
  struct sr_rt * head = sr_instance->routing_table;
  while(head){
    if (head->dest.s_addr == dest_ip){
      break;
    }
    head = head->next;
  }
  if (!head){ // destination not in routing table
    memcpy(send_ether->ether_shost, from_if->addr, ETHER_ADDR_LEN);
    memcpy(send_ether->ether_dhost, ether->ether_shost, ETHER_ADDR_LEN);
    send_ether->ether_etype = ETYPE_IP;

    /* handle ip packet */
    send_ip->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    send_ip->ip_ttl = 64;
    send_ip->ip_sum = 0;
    send_ip->ip_p = IP_PRO_ICMP;
    send_ip->ip_dst = ip->ip_src;
    send_ip->ip_src = ntohl(from_if->ip);

    /* handle icmp packet */
    sr_icmp_hdr_t * send_icmp = (sr_icmp_hdr_t *)malloc(sizeof(sr_icmp_hdr_t));
    send_icmp->icmp_type = ICMP_TYPE_DEST;
    send_icmp->icmp_code = ICMP_CODE_NET;
    send_icmp->unused = 0;
    send_icmp->icmp_sum = 0;

    /* prepare the packet */
    uint8_t * send_buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    length = 0;

    memcpy(send_buf, eth_struct_to_buf(send_ether), sizeof(sr_ethernet_hdr_t));
    length += sizeof(sr_ethernet_hdr_t);

    uint8_t * send_ip_buf = ip_struct_to_buf(send_ip);
    ((sr_ip_hdr_t *)send_ip_buf)->ip_sum = cksum(send_ip_buf, sizeof(sr_ip_hdr_t));
    memcpy(send_buf + length, send_ip_buf, sizeof(sr_ip_hdr_t));
    length += sizeof(sr_ip_hdr_t);

    uint8_t * send_icmp_buf = icmp_struct_to_buf(send_icmp);
    ((sr_icmp_hdr_t *)send_icmp)->icmp_sum = cksum(send_icmp_buf, sizeof(sr_icmp_hdr_t));
    memcpy(send_buf + length, send_icmp_buf, sizeof(sr_icmp_hdr_t));
    length += sizeof(sr_icmp_hdr_t);

    sr_send_packet(sr, send_buf, length, from);

    return;
  }

  struct sr_arpentry * arp_result = sr_arpcache_lookup(sr->arpcache, htonl(head->gw.s_addr));

  if (!arp_result){ // doesn't have arp entry
    return;
  }

  struct sr_if * to_if = sr_get_interface(sr, head->interface);

  memcpy(send_ether->ether_dhost, arp_result->mac, ETHER_ADDR_LEN);
  memcpy(send_ether->ether_shost, to_if->addr, ETHER_ADDR_LEN);
  send_ether->ether_etype = ETYPE_IP;

  memcpy(send_ip, ip, sizeof(sr_ip_hdr_t));
  send_ip->ip_ttl -= 1;
  send_ip->ip_sum = 0;

  uint8_t * send_buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + len);
  length = 0;

  memcpy(send_buf + length, send_ether, sizeof(sr_ethernet_hdr_t));
  length += sizeof(sr_ethernet_hdr_t);

  uint8_t send_ip_buf = ip_struct_to_buf(send_ip);
  ((sr_ip_hdr_t*)send_ip_buf)->ip_sum = cksum(send_ip_buf, sizeof(sr_ip_hdr_t));
  memcpy(send_buf + length, send_ip_buf, sizeof(sr_ip_hdr_t));
  length += sizeof(sr_ip_hdr_t);

  memcpy(send_buf + length, raw_ip_buf+sizeof(sr_ip_hdr_t), len-sizeof(sr_ip_hdr_t));
  length += len - sizeof(sr_ip_hdr_t);
 
  sr_send_packet(sr, send_buf, len, to_if->name);
  
}
