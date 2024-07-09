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
#include <netinet/tcp.h>
#include <pthread.h>
#include <time.h>

#include "common.h"
#include "device_table.h"
#include "device_arp_table.h"

#define BUFFER_SIZE 65536
#define CLIENT_PORT 54321

#define PACKET_SIZE 1024
#define SRC_IP "10.60.0.99" // Your source IP address
#define DST_IP "10.60.0.1" // Your destination IP address
#define SRC_MAC "\x78\x2b\xcb\x4a\x1a\xa6" // Your source MAC address
#define DST_MAC "\x2c\x4d\x54\x47\x73\x28" // Your destination MAC address
#define GRE_PROTO 0x6558
#define INTERFACE "eno1"
#define ARP_ENTRY_TIMEOUT 30
#define ARP_HASH_TABLE_SIZE  1 << 24
uint32_t CPE[ARP_HASH_TABLE_SIZE] = {0};
int CPE_length = 0;
int temp[ARP_HASH_TABLE_SIZE] = {0};

int client_sock;
int sockfd;

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
    int sockfd2;
    struct sockaddr_in target_addr;

    char buffer[PACKET_SIZE];


    if ((sockfd2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(5555);
    inet_pton(AF_INET, "10.60.0.98", &target_addr.sin_addr);

    if (setsockopt(sockfd2, SOL_SOCKET, SO_BINDTODEVICE, INTERFACE, strlen(INTERFACE)) < 0) {
        perror("setsockopt");
        close(sockfd2);
        exit(EXIT_FAILURE);
    }

    memcpy(buffer, json_data, strlen(json_data));

    if (sendto(sockfd2, buffer, strlen(json_data), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) == -1) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }
    const char *message = json_data;
    if (send(client_sock, message, strlen(message), 0) == -1) {
        perror("Error sending data to server");
        exit(EXIT_FAILURE);
    }

    //printf("Message sent to server: %s\n", message);
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
        //printf("123\n");
        struct ip *ip_hdr_gre = (struct ip*)(packet + sizeof(struct ether_header));
        device_table_insert(eth_header_gre->ether_shost, ip_hdr->ip_src.s_addr, ip_hdr_gre->ip_src.s_addr);
    }
    else{
        memcpy(eth_header_gre->ether_dhost, SRC_MAC, ETH_ALEN);
    }
    
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex("eno1:1");

    // Send the DHCP packet back
    if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        perror("sendto");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    //close(sockfd);
}

void send_tunnel_update_response(const char *packet, int packet_len) {


    struct sockaddr_ll sll;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex("eno1");

    struct ether_header *eth_header_gre = (struct ether_header *)packet;
    memcpy(eth_header_gre->ether_dhost, DST_MAC, ETH_ALEN);
    memcpy(eth_header_gre->ether_shost, SRC_MAC, ETH_ALEN);

    struct iphdr *ip_header_gre = (struct iphdr *)(packet + sizeof(struct ether_header));
    uint32_t ip_src_gre = ip_header_gre->saddr;
    ip_header_gre->saddr = ip_header_gre->daddr;
    ip_header_gre->daddr = ip_src_gre;
    
    struct ether_header * eth_hdr = (struct ether_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct gre_header));
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, SRC_MAC, ETH_ALEN);

    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct gre_header) + sizeof(struct ether_header));
    uint32_t ip_src = ip_header->saddr;
    ip_header->saddr = ip_header->daddr;
    ip_header->daddr = ip_src;

    struct udphdr *udp_hdr = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct gre_header) + sizeof(struct ether_header) + sizeof(struct iphdr));
    udp_hdr->dest = udp_hdr->source;
    udp_hdr->source = htons(55555);

    if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Send failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    //close(sockfd);
}

void process_arp(const char *packet, int packet_len) {

    struct sockaddr_ll sll;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex("eno1");


    struct ether_header *eth_header_gre = (struct ether_header *)packet;
    memcpy(eth_header_gre->ether_dhost, DST_MAC, ETH_ALEN);
    memcpy(eth_header_gre->ether_shost, SRC_MAC, ETH_ALEN);

    struct iphdr *ip_hdr_gre = (struct iphdr *)(packet + sizeof(struct ether_header));
    ip_hdr_gre->check = 0;

    struct ether_header * eth_hdr = (struct ether_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct gre_header));
    struct ether_arp * arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct gre_header) + sizeof(struct ether_header));

    if (arp_hdr->arp_op == htons(1)){
        device_table_insert(eth_hdr->ether_shost, ip_hdr_gre->saddr, ip_hdr_gre->saddr);
        uint32_t value = 0;
        memcpy(&value, arp_hdr->arp_spa, sizeof(value));
        device_arp_table_insert(eth_hdr->ether_shost, value, time(NULL));
        struct device_arp_table_entry *entry2;
          
        uint32_t arphash = *((uint32_t *)(arp_hdr->arp_tpa)) % 1000000;
        entry2 = device_arp_table_get_entry_by_ul_ip(arphash);
        if (entry2 && ((time(NULL) - entry2->timestamp)) < ARP_ENTRY_TIMEOUT){
            printf("IND-Box ARP Process\n");
            memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
            memcpy(eth_hdr->ether_shost, entry2->device_mac_addr, ETH_ALEN);
            arp_hdr->arp_op = htons(2);
            memcpy(arp_hdr->arp_tha, arp_hdr->arp_sha, 6);
            memcpy(arp_hdr->arp_tpa, arp_hdr->arp_spa, 4);
            memcpy(arp_hdr->arp_sha, entry2->device_mac_addr, 6);
            memcpy(arp_hdr->arp_spa, (u_char *)&entry2->device_ip, 4);
            ip_hdr_gre->daddr = ip_hdr_gre->saddr;
            ip_hdr_gre->saddr = inet_addr(SRC_IP);;
            ip_hdr_gre->check = csum((unsigned short *)ip_hdr_gre, sizeof(struct iphdr) / 2);

            if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
                perror("Send failed");
                close(sockfd);
                exit(EXIT_FAILURE);
            }
        }
        else{
            uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            if (memcmp(eth_hdr->ether_dhost, broadcast_mac, 6) == 0){
                device_table_insert(eth_hdr->ether_shost, ip_hdr_gre->saddr, ip_hdr_gre->saddr);
                uint32_t value = 0;
                memcpy(&value, arp_hdr->arp_spa, sizeof(value));
                device_arp_table_insert(eth_hdr->ether_shost, value, time(NULL));
                for (int i = 0; i < 1000; i++){
                    if (CPE[i] != 0){
                        if (CPE[i] != ip_hdr_gre->saddr){
                            printf("haha\n");
                            ip_hdr_gre->daddr = CPE[i];
                            ip_hdr_gre->saddr = inet_addr(SRC_IP);;
                            ip_hdr_gre->check = csum((unsigned short *)ip_hdr_gre, sizeof(struct iphdr) / 2);

                            if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
                                perror("Send failed");
                                close(sockfd);
                                exit(EXIT_FAILURE);
                            }
                        }
                    }
                    else
                        break;
                }
            }
        }
    }
    else{
        struct device_table_entry *entry;
        device_table_insert(eth_hdr->ether_shost, ip_hdr_gre->saddr, ip_hdr_gre->saddr);
        uint32_t value = 0;
        memcpy(&value, arp_hdr->arp_spa, sizeof(value));
        device_arp_table_insert(eth_hdr->ether_shost, value, time(NULL));
        uint32_t hash = hash_mac(eth_hdr->ether_dhost);
        entry = device_table_get_entry_by_ul_mac(hash);
        if (entry){
            ip_hdr_gre->saddr = inet_addr(SRC_IP);;
            ip_hdr_gre->daddr = entry->cpe_ip;
            ip_hdr_gre->check = csum((unsigned short *)ip_hdr_gre, sizeof(struct iphdr) / 2);
            if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
                perror("Send failed");
                close(sockfd);
                exit(EXIT_FAILURE);
            }
        }
    }
}

void send_dhcp_response(const char *packet, int packet_len, const char *interface, int type) {

    uint32_t crc32_hash;
    struct device_table_entry *entry;
    struct sockaddr_ll sll;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex("eno1");

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
        //printf("%d\n", crc32_hash);
        entry = device_table_get_entry_by_ul_mac(crc32_hash);
        if (entry == 0){
            printf("error when get entry\n");
            close(sockfd);
        }
        else{
            struct iphdr *ip_header_dhcp = (struct iphdr *)(packet + sizeof(struct ether_header));
            ip_header->daddr = entry->cpe_ip;
            cJSON *root = cJSON_CreateObject();
            cJSON *mac_array = cJSON_CreateArray();

            for (int i = 0; i < 6; ++i) {
                char hex_string[3]; 
                sprintf(hex_string, "%02X", entry->device_mac_addr[i]);
                cJSON_AddItemToArray(mac_array, cJSON_CreateString(hex_string));
            }
            device_table_insert(entry->device_mac_addr, entry->cpe_ip, ip_header_dhcp->daddr);
            device_arp_table_insert(entry->device_mac_addr, ip_header_dhcp->daddr, time(NULL));
            cJSON_AddItemToObject(root, "device_mac_addr", mac_array);
            cJSON_AddItemToObject(root, "cpe_ip", cJSON_CreateNumber(entry->cpe_ip));
            cJSON_AddItemToObject(root, "device_ip", cJSON_CreateNumber(ip_header_dhcp->daddr));

            char *json_data = cJSON_Print(root);

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

    if (sendto(sockfd, buffer, packet_length, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Send failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    //close(sockfd);
}

void update(const char *packet, int packet_len) {

    uint32_t crc32_hash;
    struct device_table_entry *entry;

    struct ether_header *eth_header_gre = (struct ether_header *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct gre_header));
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
    crc32_hash = hash_mac(eth_header_gre->ether_shost);
    //printf("%d\n", crc32_hash);
    entry = device_table_get_entry_by_ul_mac(crc32_hash);
    if (entry == 0){
        printf("error when get entry\n");
    }
    else{
        device_table_insert(entry->device_mac_addr, ip_hdr->ip_src.s_addr, entry->device_ip);
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *mac_array = cJSON_CreateArray();

    for (int i = 0; i < 6; ++i) {
        char hex_string[3]; 
        sprintf(hex_string, "%02X", entry->device_mac_addr[i]);
        cJSON_AddItemToArray(mac_array, cJSON_CreateString(hex_string));
    }

    cJSON_AddItemToObject(root, "device_mac_addr", mac_array);
    cJSON_AddItemToObject(root, "cpe_ip", cJSON_CreateNumber(ip_hdr->ip_src.s_addr));
    cJSON_AddItemToObject(root, "device_ip", cJSON_CreateNumber(entry->device_ip));

    char *json_data = cJSON_Print(root);

    device_info(json_data);

    cJSON_Delete(root);
    free(json_data);
}

// Function to handle TCP client

// int client_sock;
void *handleTCPClient(void *arg) {
    //int client_sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    // Create TCP socket
    if ((client_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("Error creating client socket");
        return 0;
    }

    // Initialize server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    if (inet_pton(AF_INET, "10.60.0.98", &server_addr.sin_addr) <= 0) {
        printf("Invalid server IP address");
        return 0;
    }

    // Connect to server
    if (connect(client_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        printf("Error connecting to server");
        return 0;
    }

    // Send data to server
    const char *message = "Hello, TCP Server!";
    if (send(client_sock, message, strlen(message), 0) == -1) {
        printf("Error sending data to server");
        return 0;
    }

    printf("Message sent to server: %s\n", message);

    return NULL;
}

void *handleL2RawSocket(void *arg){

    // Create a raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        printf("L2 error");
        return 0;
    }

    // Bind to a specific network interface
    struct sockaddr_ll sll;
    memset((struct sockaddr *)&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex("eno1");
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        printf("L2 error");
        close(sockfd);
        return 0;
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

        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_hdr = (struct ip*)(buffer + sizeof(struct ether_header));
            uint32_t ip_addr = ip_hdr->ip_dst.s_addr;
            uint32_t ip_addr2 = ip_hdr->ip_src.s_addr;

            if (ip_hdr->ip_p == IPPROTO_GRE) {
                struct ether_header *eth_hdr_gre = (struct ether_header *)(buffer + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct gre_header));
                if (ntohs(eth_hdr_gre->ether_type) == ETHERTYPE_IP){
                    struct ip *ip_hdr_gre = (struct ip *)(buffer + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct gre_header) + sizeof(struct ether_header));
                    if (ip_hdr_gre->ip_p == IP_PROTO_UDP){
                        struct udphdr *udp_hdr_gre = (struct udphdr*)(buffer + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct gre_header) + sizeof(struct ether_header) + sizeof(struct ip));
                        if (ntohs(udp_hdr_gre->source) == 68){
                            send_dhcp_request(buffer, len, "eno1");
                            if (!(temp[ip_addr2%1000000])){
                                printf("hehe\n");
                                CPE[CPE_length] = ip_addr2;
                                CPE_length++;
                                temp[ip_addr2%1000000] = 1;
                            }
                        }
                        else if (ntohs(udp_hdr_gre->source) == 33333){
                            printf("update\n");
                            update(buffer, len);
                            send_tunnel_update_response(buffer, len);
                        }
                    }
                }
                else if(ntohs(eth_hdr_gre->ether_type) == ETHERTYPE_ARP && ip_addr == 1660959754){
                    //printf("ARP Process\n");
                    process_arp(buffer, len);
                }   
                
            }
            else if (ip_hdr->ip_p == IP_PROTO_UDP){
                struct udphdr *udp_hdr = (struct udphdr*)(buffer + sizeof(struct ether_header) + sizeof(struct ip));
                if(ntohs(udp_hdr->source) == 67){
                    send_dhcp_response(buffer, len, "eno1", 1);
                }

            }
            // else if (ip_hdr->ip_p == IP_PROTO_TCP){
            //     struct tcphdr * tcp_hdr = (struct tcphdr*)(buffer + sizeof(struct ether_header) + sizeof(struct ip));
            //     printf("TCP\n");
            //     if(ntohs(tcp_hdr->source) == 20)
            //         process_tcp_packet(buffer, len);
            // }
        }

    }

    return EXIT_SUCCESS;
}

int main(){
    pthread_t l2_thread, client_thread;

    // Create thread for handling L2 raw socket
    if (pthread_create(&l2_thread, NULL, handleL2RawSocket, NULL)) {
        printf("Error creating L2 raw socket thread");
        return EXIT_FAILURE;
    }

    // Create thread for TCP client
    if (pthread_create(&client_thread, NULL, handleTCPClient, NULL)) {
        printf("Error creating client thread");
        return EXIT_FAILURE;
    }

    // Wait for threads to finish
    pthread_join(l2_thread, NULL);
    pthread_join(client_thread, NULL);

    return EXIT_SUCCESS;
}