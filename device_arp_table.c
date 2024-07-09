#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "common.h"
#include "device_arp_table.h"

static struct device_arp_table_entry *arp_hash_table[ARP_HASH_TABLE_SIZE];

int device_arp_table_insert(uint8_t device_mac_addr[6], uint32_t device_ip, time_t timestamp)
{
    uint32_t table_idx = ARP_HASK_TABLE_INDEX_MASK;
    struct device_arp_table_entry *entry;
    table_idx = hash_arp(device_ip);

    entry = device_arp_table_get_entry_by_ul_ip(table_idx);

    if (entry) {
        memcpy(entry->device_mac_addr, device_mac_addr, 6);
    	entry->device_ip = device_ip;
        entry->timestamp = timestamp;

    	arp_hash_table[table_idx] = entry;
        return 0;
    }

    entry = (struct device_arp_table_entry *)malloc(sizeof(struct device_arp_table_entry));
    if (entry == NULL){
        printf("error when allocate space\n");
    }

    memcpy(entry->device_mac_addr, device_mac_addr, 6);
    entry->device_ip = device_ip;
    entry->timestamp = timestamp;

    arp_hash_table[table_idx] = entry;

    return 0;
}

struct device_arp_table_entry* device_arp_table_get_entry_by_ul_ip(uint32_t hash)
{
    struct device_arp_table_entry *cp;

    cp = arp_hash_table[hash];
    if (cp) {
        return cp;
    }

    return 0;
}

unsigned int hash_arp(uint32_t device_ip){
    unsigned int hash = 0;
    // for (int i = 0; i < 6; i++){
    //  hash += device_mac_addr[i];
    //  hash *= 5;
    // }
    //printf("IP:%u\n", device_ip);
    hash = device_ip % 1000000;
    //printf("first:%u\n", hash);
    return hash;
}