#ifndef sr_PACKETUTIL_H
#define sr_PACKETUTIL_H

#include "sr_protocol.h"
#include "sr_arpcache.h"

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

#endif

struct sr_instance;

void process_arp_packet(struct sr_instance *, sr_ethernet_hdr_t *, sr_arp_hdr_t *, char *, uint8_t *, int);
void process_ip_packet(struct sr_instance *, uint8_t *, sr_ethernet_hdr_t *, sr_ip_hdr_t *, char *, int);
void copy_id_hdr(sr_ip_hdr_t *, sr_ip_hdr_t *);
void sweep_req(struct sr_packet *, uint8_t *, struct sr_instance *);
