#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <pcap.h>
// #include <pcap.h>
#include "common.h"

#define INTERFACE_ENO1 "eno1"
#define INTERFACE_ENO1_1 "eno1"

void processGtpDhcpPacket(const unsigned char *packet, int packetSize, pcap_t *eno1_1_handle) {
    // struct ether_header *eth_header = (struct ether_header *)packet;
    // struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    // struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    // const uint16_t gtp_ext_hdr_len = calculate_gtp_ext_hdr_len(sizeof(struct ran_container_type1) + 2);
    // uint16_t pdcp_hdr_len = 3;
    // struct ip *ip_gre = (struct ip *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)
    //     + sizeof(struct gtp_hdr) - 4 + sizeof(struct gtp_ext_info) + gtp_ext_hdr_len + pdcp_hdr_len + sizeof(struct sdap_hdr));

    packet += (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct gre_header));

    packetSize -= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct gre_header));

    if (pcap_sendpacket(eno1_1_handle, packet, packetSize) != 0) {
        fprintf(stderr, "Failed to send packet to %s: %s\n", INTERFACE_ENO1_1, pcap_geterr(eno1_1_handle));
        exit(EXIT_FAILURE);
    }

    printf("Sent processed packet to %s. Size: %d\n", INTERFACE_ENO1_1, packetSize);
}

void processDhcpPacket(const unsigned char *packet, int packetSize, pcap_t *eno1_1_handle) {
    // struct ether_header *eth_header = (struct ether_header *)packet;
    // struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    // struct in_addr src_addr = ip_header->ip_src;
    // struct in_addr dst_addr = ip_header->ip_dst;
    // char src_ip_addr[INET_ADDRSTRLEN];
    // char dst_ip_addr[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &src_addr, src_ip_addr, INET_ADDRSTRLEN);
    // inet_ntop(AF_INET, &dst_addr, dst_ip_addr, INET_ADDRSTRLEN);
    // printf("src IP: %s\n", src_ip_addr);
    // printf("dst IP: %s\n", dst_ip_addr);

    // struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    // const uint16_t gtp_ext_hdr_len = calculate_gtp_ext_hdr_len(sizeof(struct ran_container_type1) + 2);
    // uint16_t pdcp_hdr_len = 3;
    // struct ip *ip_gre = (struct ip *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)
    //     + sizeof(struct gtp_hdr) - 4 + sizeof(struct gtp_ext_info) + gtp_ext_hdr_len + pdcp_hdr_len + sizeof(struct sdap_hdr));
    // packet += (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)
    //     + sizeof(struct gtp_hdr) - 4 + sizeof(struct gtp_ext_info) + gtp_ext_hdr_len + pdcp_hdr_len + sizeof(struct sdap_hdr) + sizeof(struct ip) + sizeof(struct gre_header));
    // size_t greAndOriginalSize = sizeof(struct gre_header) + packetSize;
    // unsigned char *greAndOriginalPacket = (unsigned char *)malloc(greAndOriginalSize);
    // struct gre_header *gre_hdr = (struct gre_header *)greAndOriginalPacket;
    // gre_hdr->c = 0;
    // gre_hdr->k = 0;
    // gre_hdr->s = 0;
    // gre_hdr->res1 = 0;
    // gre_hdr->ver = 0;
    // gre_hdr->proto = 0x6558;
    // memcpy(greAndOriginalPacket + sizeof(struct gre_header), packet, packetSize);

    size_t greAndIPv4AndDHCPSize = sizeof(struct gre_header) + sizeof(struct iphdr) + sizeof(struct ether_header) + packetSize;
    unsigned char *greAndIPv4AndDHCPPacket = (unsigned char *)malloc(greAndIPv4AndDHCPSize);

    size_t length = greAndIPv4AndDHCPSize;
    struct ether_header *eth_hdr = (struct ether_header *)greAndIPv4AndDHCPPacket;
    uint8_t dest_mac[] = {0x2c, 0x4d, 0x54, 0x47, 0x73, 0x28};
    uint8_t src_mac[] = {0x78, 0x2b, 0xcb, 0x4a, 0x1a, 0xa6};
    memcpy(eth_hdr->ether_dhost, dest_mac, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, src_mac, ETH_ALEN);
    eth_hdr->ether_type = htons(ETH_P_IP);

    length -= sizeof(struct ether_header);
    struct iphdr *ipv4Header = (struct iphdr *)(greAndIPv4AndDHCPPacket + sizeof(struct ether_header));
    ipv4Header->version = 4;  // IPv4 version
    ipv4Header->ihl = 5;  // Header length (5 words)
    ipv4Header->tos = 0;  // Type of service
    ipv4Header->tot_len = htons(length);  // Total length
    ipv4Header->id = htons(12345);  // Identification
    ipv4Header->frag_off = 0;  // Fragment offset
    ipv4Header->ttl = 64;  // Time to live
    ipv4Header->protocol = IPPROTO_GRE;  // Protocol type (17 for UDP, adjust as needed)
    ipv4Header->check = 0;  // Set to 0 for now; checksum calculation can be done later
    // struct in_addr src_addr1, dest_addr1;
    // inet_pton(AF_INET, "10.60.0.99", &src_addr1);
    // inet_pton(AF_INET, "10.60.0.1", &dest_addr1);
    ipv4Header->saddr = inet_addr("10.60.0.99");  // Source IP address
    ipv4Header->daddr = inet_addr("10.60.0.1");

    // Create a GRE header
    struct gre_header *greHeader = (struct gre_header *)(greAndIPv4AndDHCPPacket + sizeof(struct ether_header) + sizeof(struct iphdr));
    //greHeader->flags = htons(0x2000);  // Set GRE flags (basic GRE header with no options)
    greHeader->c = 0;
    greHeader->k = 0;
    greHeader->s = 0;
    greHeader->res1 = 0;
    greHeader->ver = 0;
    greHeader->proto = htons(0x6558);  // Set protocol type to IPv4

    // Create an IPv4 header
    

    // Copy the DHCP packet after the IPv4 header
    memcpy(greAndIPv4AndDHCPPacket + sizeof(struct gre_header) + sizeof(struct ip), packet, packetSize);

    if (pcap_sendpacket(eno1_1_handle, greAndIPv4AndDHCPPacket, greAndIPv4AndDHCPSize) != 0) {
        fprintf(stderr, "Failed to send packet to %s: %s\n", INTERFACE_ENO1_1, pcap_geterr(eno1_1_handle));
        exit(EXIT_FAILURE);
    }

    printf("Sent processed packet to %s. Size: %d\n", INTERFACE_ENO1_1, packetSize);
}

void packetHandler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    pcap_t *eno1_1_handle = (pcap_t *)user;
    struct ether_header *eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        if (ip_header->ip_p == IPPROTO_GRE) {
            // struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            processGtpDhcpPacket(packet, pkthdr->len, eno1_1_handle);
            // printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
            // printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
            // if (ntohs(udp_header->uh_sport) == 2123){
            //     printf("ha1\n");
                
            // }
            // else if (ntohs(udp_header->uh_sport) == 67){
            //     processDhcpPacket(packet, pkthdr->len, eno1_1_handle);
            // }
        }
        else if (ip_header->ip_p == IPPROTO_UDP){
            processDhcpPacket(packet, pkthdr->len, eno1_1_handle);
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *eno1_handle, *eno1_1_handle;

    // ¥´? eno1 ÊI¥d?¦æ§ì¥]
    eno1_handle = pcap_open_live(INTERFACE_ENO1, 65536, 1, 1000, errbuf);
    if (eno1_handle == NULL) {
        fprintf(stderr, "Could not open interface %s: %s\n", INTERFACE_ENO1, errbuf);
        exit(EXIT_FAILURE);
    }

    eno1_1_handle = pcap_open_live(INTERFACE_ENO1_1, 65536, 1, 1000, errbuf);
    if (eno1_1_handle == NULL) {
        fprintf(stderr, "Could not open interface %s: %s\n", INTERFACE_ENO1_1, errbuf);
        pcap_close(eno1_handle);
        exit(EXIT_FAILURE);
    }

    pcap_loop(eno1_handle, 0, packetHandler, (unsigned char *)eno1_1_handle);
    //pcap_loop(eno1_1_handle, 0, packetHandler2, (unsigned char *)eno1_handle);

    // ?? pcap ¥y¬`
    pcap_close(eno1_handle);
    pcap_close(eno1_1_handle);

    return 0;
}
