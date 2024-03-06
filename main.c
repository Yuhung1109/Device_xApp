#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include "common.h"
#include "device_table.h"
#include "device_arp_table.h"

#define BUFFER_SIZE 65536

#define PACKET_SIZE 1024
#define SRC_IP "10.60.0.99" // Your source IP address
#define DST_IP "10.60.0.1" // Your destination IP address
#define SRC_MAC "\x78\x2b\xcb\x4a\x1a\xa6" // Your source MAC address
#define DST_MAC "\x2c\x4d\x54\x47\x73\x28" // Your destination MAC address
#define GRE_PROTO 0x6558
#define INTERFACE "eno1"

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

void print_mac_address(unsigned char *mac_address) {
    printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac_address[0], mac_address[1], mac_address[2],
           mac_address[3], mac_address[4], mac_address[5]);
}

void device_info(char *json_data){
    int sockfd;
    struct sockaddr_in target_addr;

    char buffer[PACKET_SIZE];

    printf("send device info\n");

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int broadcast_enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) < 0) {
        perror("setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(5555);
    inet_pton(AF_INET, "255.255.255.255", &target_addr.sin_addr);

    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, INTERFACE, strlen(INTERFACE)) < 0) {
        perror("setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    memcpy(buffer, json_data, strlen(json_data));

    if (sendto(sockfd, buffer, strlen(json_data), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) == -1) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }
    else
        printf("send device info success\n");
    close(sockfd);
}

// Function to send the DHCP packet back
void send_dhcp_request(const char *packet, int packet_len, const char *interface) {

    uint32_t crc32_hash;
    struct device_table_entry *entry;

    //struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));

    packet += (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct gre_header));

    packet_len -= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct gre_header));

    struct ether_header *eth_header_gre = (struct ether_header *)(packet);
    if (ntohs(eth_header_gre->ether_type) != ETHERTYPE_ARP){
        struct ip *ip_hdr_gre = (struct ip*)(packet + sizeof(struct ether_header));
        device_table_insert(eth_header_gre->ether_shost, ip_hdr->ip_src.s_addr, ip_hdr_gre->ip_src.s_addr);
    }
    // else{
    //     packet_len -= 18;
    // }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Prepare sockaddr_ll
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex("eno1:1");

    // Send the DHCP packet back
    if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        perror("sendto");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    //printf("Finish DHCP Request\n");

    close(sockfd);
}

void send_dhcp_response(const char *packet, int packet_len, const char *interface, int type) {

    uint32_t crc32_hash;
    struct device_table_entry *entry;
    int sockfd;
    struct sockaddr_ll dest_addr;
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ALL);
    dest_addr.sll_ifindex = if_nametoindex("eno1");

    struct ether_header *eth_header_dhcp = (struct ether_header *)packet;
    // Buffer to hold the packet
    unsigned char buffer[PACKET_SIZE];
    memset(buffer, 0, PACKET_SIZE);

    // Ethernet header
    struct ether_header *eth_header = (struct ether_header *)buffer;
    memcpy(eth_header->ether_dhost, DST_MAC, ETH_ALEN);
    memcpy(eth_header->ether_shost, SRC_MAC, ETH_ALEN);
    eth_header->ether_type = htons(ETH_P_IP);

    // IP header
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ether_header));
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(packet_len + sizeof(struct iphdr) + sizeof(struct gre_header));
    ip_header->id = htons(12345);
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_GRE;
    ip_header->check = 0; // Leave checksum 0 now, filled later by pseudo header
    ip_header->saddr = inet_addr(SRC_IP);
    //ip_header->daddr = inet_addr(DST_IP);
    if (type == 1){
        crc32_hash = hash_mac(eth_header_dhcp->ether_dhost);
        entry = device_table_get_entry_by_ul_mac(crc32_hash);
        if (entry == 0){
            printf("error when get entry\n");
            close(sockfd);
        }
        else{
            struct iphdr *ip_header_dhcp = (struct iphdr *)(packet + sizeof(struct ether_header));
            ip_header->daddr = entry->cpe_ip;
            // cJSON *root = cJSON_CreateObject();
            // cJSON *mac_array = cJSON_CreateArray();
            // for (int i = 0; i < 6; i++) {
            //     char hex_string[3]; 
            //     sprintf(hex_string, "%02X", entry->device_mac_addr[i]);
            //     cJSON_AddItemToArray(mac_array, cJSON_CreateString(hex_string));
            // }
            // cJSON_AddItemToObject(root, "device_mac", mac_array);
            // cJSON_AddNumberToObject(root, "device_ip", entry->device_ip);
            // cJSON_AddNumberToObject(root, "cpe_ip", entry->cpe_ip);
            // char *json_data = cJSON_Print(root);
            // device_info(json_data);
            cJSON *root = cJSON_CreateObject();
            cJSON *mac_array = cJSON_CreateArray();

            // ???MAC¦a§}???JSON??
            for (int i = 0; i < 6; ++i) {
                char hex_string[3]; 
                sprintf(hex_string, "%02X", entry->device_mac_addr[i]);
                cJSON_AddItemToArray(mac_array, cJSON_CreateString(hex_string));
            }

            // ?¦U?¦r¬q²K¥[¨ìJSON?¶H¤¤
            cJSON_AddItemToObject(root, "device_mac_addr", mac_array);
            cJSON_AddItemToObject(root, "cpe_ip", cJSON_CreateNumber(entry->cpe_ip));
            cJSON_AddItemToObject(root, "device_ip", cJSON_CreateNumber(ip_header_dhcp->daddr));

            // ? cJSON ?¶H???JSON®æ¦¡ªº¦r²Å¦ê
            char *json_data = cJSON_Print(root);

            // ¥´¦LJSON®æ¦¡ªº¦r²Å¦ê
            printf("JSON string:\n%s\n", json_data);
            device_info(json_data);
            cJSON_Delete(root);
            free(json_data);
        }
    }
    else{
        ip_header->daddr = inet_addr(DST_IP);
    }

    // GRE header
    struct gre_header *gre_hdr = (struct gre_header *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    //gre_hdr->flags = 0;
    gre_hdr->proto = htons(GRE_PROTO);

    // Calculate IP checksum
    ip_header->check = csum((unsigned short *)ip_header, sizeof(struct ip) / 2);

    memcpy(buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct gre_header), packet, packet_len); // °²?dhcp_packet©Mdhcp_packet_length¤w©w?

    int packet_length = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct gre_header) + packet_len;

    if (sendto(sockfd, buffer, packet_length, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Send failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);
}

int main() {
    // Create a raw socket
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    // Bind to a specific network interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex("eno1");
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("bind");
        close(sockfd);
        return EXIT_FAILURE;
    }

    // Buffer to hold the received packet
    unsigned char buffer[BUFFER_SIZE];

    // Receive and process packets
    while (1) {
        int len = recv(sockfd, buffer, BUFFER_SIZE, 0);
        if (len == -1) {
            perror("recv");
            continue;
        }

        // Check if the packet is IPv4 and GRE encapsulated
        struct ether_header *eth_header = (struct ether_header *)buffer;
        //struct ip *ip_header = (struct ip *)(buffer + sizeof(struct ether_header));
        //struct ethhdr *eth = (struct ethhdr*)buffer;
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_hdr = (struct ip*)(buffer + sizeof(struct ether_header));
            uint32_t ip_addr = ip_hdr->ip_dst.s_addr;
            if (ip_hdr->ip_p == IPPROTO_GRE) {
                uint32_t subnet = 0x0A3C0063;
                uint32_t mask = 0xFFFFFFFF;
                uint32_t ip_addr = ip_hdr->ip_dst.s_addr;
                //(ip_addr & mask) == (subnet & mask)
                if (ip_addr == 1660959754){ //IP=10.60.0.99
                    //printf("DHCP Request\n");
                    send_dhcp_request(buffer, len, "eno1");
                }
            }
            else if (ip_hdr->ip_p == IP_PROTO_UDP){
                struct udphdr *udp_hdr = (struct udphdr*)(buffer + sizeof(struct ether_header) + sizeof(struct ip));
                if(ntohs(udp_hdr->source) == 67){
                    printf("DHCP offer\n");
                    //device_arp_table_insert(eth_header->ether_dhost, ip_hdr->ip_dst.s_addr);
                    //device_table_insert(eth_header->ether_dhost, ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr);
                    send_dhcp_response(buffer, len, "eno1", 1);
                }
            }
        }
        else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
            uint8_t expected_mac_address[6] = {0x78, 0x2b, 0xcb, 0x4a, 0x1a, 0xa6};
            //printf("%X\n", eth_header->ether_shost);
            if (memcmp(eth_header->ether_shost, expected_mac_address, 6) == 0){
                send_dhcp_response(buffer, len, "eno1", 0);
            }
        }

    }

    close(sockfd);
    return EXIT_SUCCESS;
}