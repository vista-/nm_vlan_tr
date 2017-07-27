#define _GNU_SOURCE
#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <endian.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <linux/if_tun.h>

#define ETH_HDR_LEN 18

// Length of an Ethernet footer (CRC checksum)
#define ETH_FTR_LEN 4

// Time to wait before the link comes up
#define WAIT_LINK 3

#define VLAN_MASK 0xFF0F
#define PRIO_MASK 0x00F0

u_short vlan_assign[65536] = { 0 };

u_char if_addr[6];

static int abort_processing = 0;
static unsigned long* packetcount = NULL;

struct __attribute__((packed)) ethernet_header {
  u_char dsthost[6];        // Destination host MAC
  u_char srchost[6];        // Source host MAC
  u_short vlan_tag_id;      // Should be 0x8100
  u_short vlan_tci;         // Last 12 bits is the VLAN ID itself, first 4 is priority and the evil bit
  u_short ethertype;        // Ethertype field
};

// Rewrite packets meant to be transmitted back onto the wire. Returns the rewritten VLAN tag value in LE.
u_short rewrite_vlan_wire(u_char* pkt) {
  struct ethernet_header* eth = (struct ethernet_header*) pkt;
  //memcpy(eth->srchost, if_addr, 6);

  // Look for 802.1Q header
  if(ntohs(eth->vlan_tag_id) != 0x8100) {
    return 0;
  }

  // Check if we have a valid VLAN assignment for the packet, if not, then we should just drop it
  if(vlan_assign[eth->vlan_tci & VLAN_MASK] == 0) {
    return 0;
  }

  // Rewrite VLAN tag
  eth->vlan_tci = (eth->vlan_tci & PRIO_MASK) | (vlan_assign[eth->vlan_tci & VLAN_MASK]);

  // Return with new VLAN ID
  return eth->vlan_tci & VLAN_MASK;
}

// Handler for C-c
void sigint_handler(int signal) {
  abort_processing = 1;
}

// Display a PPS counter.
void* pps_display(void* arg) {
  while(!abort_processing) {
    sleep(1);
    printf("%lu pps\n", *packetcount);
    *packetcount = 0;
  }

  return 0;
}

// Count the amount of free slots on a device. From bridge.c
int pkt_queued(struct nm_desc *d, int tx) {
  u_int i, tot = 0;

  if (tx) {
    for (i = d->first_tx_ring; i <= d->last_tx_ring; i++) {
      tot += nm_ring_space(NETMAP_TXRING(d->nifp, i));
    }
  } else {
    for (i = d->first_rx_ring; i <= d->last_rx_ring; i++) {
      tot += nm_ring_space(NETMAP_RXRING(d->nifp, i));
    }
  }
  return tot;
}

void packet_loop(struct nm_desc* nd, struct pollfd* netmap_fds) {

  // The packet buffer
  u_char* pkt;

  // The packet header (contains length information)
  struct nm_pkthdr pkthdr;
  long int count;

  // Main "event" loop
  while(!abort_processing) {
    netmap_fds[0].events = POLLIN;
    u_int tx_left = pkt_queued(nd, 1);

    if(!tx_left) {
      netmap_fds[0].events |= POLLOUT;
    }

    // This ifdef sets the POLLOUT event to be constantly polled, causing the NIC to constantly dump the prepared packets. Set with -DPOLLOUT when compiling
    #ifdef CPOLLOUT
      netmap_fds[0].events |= POLLOUT;
    #endif

    poll(netmap_fds, 1, 2500);
    // If there are no packets queued up, just go back to polling
    if(!(netmap_fds[0].revents & POLLIN)) continue;

    u_int src_ring_i = nd->first_rx_ring;
    u_int dst_ring_i = nd->first_tx_ring;

    while(src_ring_i <= nd->last_rx_ring && dst_ring_i <= nd->last_tx_ring) {
      struct netmap_ring* src_ring = NETMAP_RXRING(nd->nifp, src_ring_i);
      struct netmap_ring* dst_ring = NETMAP_TXRING(nd->nifp, dst_ring_i);

      if(nm_ring_empty(src_ring)) {
        src_ring_i++;
        continue;
      }

      if(nm_ring_empty(dst_ring)) {
	dst_ring_i++;
	continue;
      }

      // A base limit for moving packets in batches
      u_int limit = 1024;
      u_int m = nm_ring_space(src_ring);

      if (m < limit) {
        limit = m;
      }

      m = nm_ring_space(dst_ring);
      if (m < limit) {
        limit = m;
      }

      u_int src = src_ring->cur;
      u_int dst = dst_ring->cur;

      while(limit-- > 0) {

        u_int src_idx;
        struct netmap_slot* src_slot;
        struct netmap_slot* dst_slot;

        src_slot = &src_ring->slot[src];
        src_idx = src_slot->buf_idx;

        pkt = (u_char*)NETMAP_BUF(src_ring, src_idx);
        pkthdr.len = pkthdr.caplen = src_slot->len;

	{{
            (*packetcount)++;
            count++;
            // This ifdef sends a TX sync using ioctl every 64 packets. Set with -DIOCTL. Recommended!
            #ifdef IOCTL
              if(count % 64 == 0) {
                ioctl(NETMAP_FD(nd), NIOCTXSYNC);
              }
            #endif

            if(rewrite_vlan_wire(pkt) == 0) {
              src = nm_ring_next(src_ring, src);
              continue;
            }

            dst_slot = &dst_ring->slot[dst];

            u_int tmp_idx = dst_slot->buf_idx;
            dst_slot->buf_idx = src_slot->buf_idx;
            src_slot->buf_idx = tmp_idx;
            u_int tmp_len = dst_slot->len;
            dst_slot->len = src_slot->len;
            src_slot->len = tmp_len;
            src_slot->flags |= NS_BUF_CHANGED;
            dst_slot->flags |= NS_BUF_CHANGED;

            src = nm_ring_next(src_ring, src);
            dst = nm_ring_next(dst_ring, dst);
        }}
      }
      // At the end of a batch move, set the cur and head ptrs on the rings
      src_ring->cur = src;
      src_ring->head = src_ring->cur;
      dst_ring->cur = dst;
      dst_ring->head = dst_ring->cur;
      #ifdef IOCTL_FIX
        /* if(count > 64) { */
	/*   count = 0; */
          ioctl(NETMAP_FD(nd), NIOCTXSYNC);
        /* } */
      #endif
    }
  }
}

// Gets the MAC address from a given interface and sets the global variable
void set_hw_addr(char* ifname) {
  struct ifreq ifr;
  struct sockaddr_in addr;
  int s;

  memset(&ifr, 0, sizeof(ifr));
  memset(&addr, 0, sizeof(addr));
  strncpy(ifr.ifr_name, strchr(ifname, ':') + 1, IFNAMSIZ);

  addr.sin_family = AF_INET;
  s = socket(addr.sin_family, SOCK_DGRAM, 0);

  if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl hw addr");
  }

  memcpy(if_addr, ifr.ifr_hwaddr.sa_data, 6);

  close(s);
}

int main(int argc, char** argv) {
  struct nm_desc* nd = NULL;

  struct pollfd netmap_fds[1];
  vlan_assign[htons(3000)] = htons(3001);
  vlan_assign[htons(3001)] = htons(3000);
  char *ifname, *ifname_m;

  pthread_t thread_id;

  if(argc == 1) {
    printf("usage: nm_vlan_tr [if]\n");
    return 2;
  }

  // The interface name (beginning with "netmap:" hopefully) is the 1st arg
  ifname = argv[1];
  // Get the HW address from the interface and save it
  set_hw_addr(ifname);

  packetcount = (unsigned long*) malloc(sizeof(unsigned long));

  if(packetcount == NULL) {
    fprintf(stderr, "Malloc failed for 'packetcount'\n");
    return 1;
  }

  // Open Netmap interface on 1st arg if RX
  asprintf(&ifname_m, "%s", ifname);
  nd = nm_open(ifname_m, NULL, 0, 0);
  if(nd == NULL) {
    fprintf(stderr, "Cannot open interface %s\n", ifname);
    return 1;
  }

  // Poll on main interface
  netmap_fds[0].fd = NETMAP_FD(nd);

  // Install signal handler for C-c
  signal(SIGINT, sigint_handler);

  // ifdef for a packets per second display, enable with -DPPS_DISP
  #ifdef PPS_DISP
    // Start pps display thread
    pthread_create(&thread_id, NULL, &pps_display, NULL);
  #endif

  // Wait for the link to come up... should be about 2-3 secs
  sleep(WAIT_LINK);
  printf("Ready for use\n");

  // Start the packet loop
  packet_loop(nd, netmap_fds);

  exit(0);
}
