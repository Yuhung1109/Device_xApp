#ifndef Device_TABLE_H_
#define Device_TABLE_H_

#include <stdint.h>
#include <math.h>

// Table size = 2 ^ 20 (1048576)
#define Device_HASH_TABLE_SIZE  1 << 24
#define Device_HASK_TABLE_INDEX_MASK (Device_HASH_TABLE_SIZE - 1)

struct device_table_entry {
	uint8_t device_mac_addr[6];
	uint32_t cpe_ip;
	uint32_t device_ip;
};

unsigned int hash_mac(uint8_t device_mac_addr[6]);

int device_table_insert(uint8_t device_mac_addr[6], uint32_t cpe_ip, uint32_t device_ip);
struct device_table_entry* device_table_get_entry_by_ul_mac(uint32_t hash);

#endif