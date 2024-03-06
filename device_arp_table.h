#ifndef Device_ARP_TABLE_H_
#define Device_ARP_TABLE_H_

#include <stdint.h>
#include <math.h>

// Table size = 2 ^ 20 (1048576)
#define ARP_HASH_TABLE_SIZE  1 << 24
#define ARP_HASK_TABLE_INDEX_MASK (ARP_HASH_TABLE_SIZE - 1)

struct device_arp_table_entry {
	uint8_t device_mac_addr[6];
	uint32_t device_ip;
};

unsigned int hash_arp(uint32_t device_ip);

int device_arp_table_insert(uint8_t device_mac_addr[6], uint32_t device_ip);
struct device_arp_table_entry* device_arp_table_get_entry_by_ul_ip(uint32_t hash);

#endif