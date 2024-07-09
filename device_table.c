#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

#include "common.h"
#include "device_table.h"

static struct device_table_entry *device_hash_table[Device_HASH_TABLE_SIZE];

int device_table_insert(uint8_t device_mac_addr[6], uint32_t cpe_ip, uint32_t device_ip)
{
    uint32_t table_idx = Device_HASK_TABLE_INDEX_MASK;
    struct device_table_entry *entry;
    table_idx = hash_mac(device_mac_addr);
    entry = device_table_get_entry_by_ul_mac(table_idx);

    if (entry) {
        memcpy(entry->device_mac_addr, device_mac_addr, 6);
        entry->cpe_ip = cpe_ip;
        entry->device_ip = device_ip;

        device_hash_table[table_idx] = entry;
        return 0;
    }
    // else{
    //     printf("Device MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", device_mac_addr[0], device_mac_addr[1],
    //        device_mac_addr[2], device_mac_addr[3], device_mac_addr[4], device_mac_addr[5]);
    //     printf("CPE IP: %u\n", cpe_ip);
    //     printf("Device IP: %u\n", device_ip);
    // }
    entry = (struct device_table_entry *)malloc(sizeof(struct device_table_entry));
    if (entry == NULL){
        printf("error when allocate space\n");
    }
    
    memcpy(entry->device_mac_addr, device_mac_addr, 6);
    entry->cpe_ip = cpe_ip;
    entry->device_ip = device_ip;

    device_hash_table[table_idx] = entry;
    if (entry == NULL)
        printf("error when insert device info\n");

    return 0;
}

struct device_table_entry* device_table_get_entry_by_ul_mac(uint32_t hash)
{
    struct device_table_entry *cp;

    cp = device_hash_table[hash];
    if (cp) {
        return cp;
    }

    return 0;
}

unsigned int hash_mac(uint8_t device_mac_addr[6]){
    unsigned int hash = 0;
    for (int i = 0; i < 6; i++){
        hash += device_mac_addr[i];
        hash *= 5;
    }
    return hash;
}