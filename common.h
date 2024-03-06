#ifndef xApp_COMMON_
#define xApp_COMMON_

#include <stdint.h>
#include <math.h>

// Table size = 2 ^ 20 (1048576)
// #define Device_HASH_TABLE_SIZE  1 << 24
// #define Device_HASK_TABLE_INDEX_MASK (Device_HASH_TABLE_SIZE - 1)

// struct pdcp_hdr_sn_12 {
//     uint8_t pdcp_sn_first_4_bits : 4;
//     uint8_t reserved : 3;
//     uint8_t DC : 1;

//     uint8_t pdcp_sn_last_8_bits;
// };

// struct pdcp_hdr_sn_18 {
//     uint8_t pdcp_sn_first_2_bits : 2;
//     uint8_t reserved : 5;
//     uint8_t DC : 1;

//     uint16_t pdcp_sn_last_16_bits;
// };
struct gre_header {
    uint16_t res2:4;
	uint16_t s:1;
 	uint16_t k:1;
 	uint16_t res1:1;
 	uint16_t c:1;
 	uint16_t ver:3;
 	uint16_t res3:5;
 	uint16_t proto;
};

// struct gtp_hdr {
//     uint8_t msg_type;
//  	uint16_t plen;
//  	uint32_t teid;
// 	uint8_t gtp_hdr_info;
//  	uint8_t pn:1;
//  	uint8_t s:1;
//  	uint8_t e:1;
//  	uint8_t res1:1;
//  	uint8_t pt:1;
//  	uint8_t ver:3;
// };

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define IP_PROTO_SCTP 132

#define UDP_PORT_UE5G 9527

// #define GTP_MSG_TYPE_G_PDU 255
// #define GTP_EXT_HDR_TYPE_NR_RAN_CONTAINER 0b10000100

// struct drb_ind_hdr {
//     uint8_t drb_id : 6;
//     uint8_t R: 1;
//     uint8_t sdap_hdr_presence : 1;
// };

// struct pdcp_hdr_sn_12 {
//     uint8_t pdcp_sn_first_4_bits : 4;
//     uint8_t reserved : 3;
//     uint8_t DC : 1;

//     uint8_t pdcp_sn_last_8_bits;
// };

// struct pdcp_hdr_sn_18 {
//     uint8_t pdcp_sn_first_2_bits : 2;
//     uint8_t reserved : 5;
//     uint8_t DC : 1;

//     uint16_t pdcp_sn_last_16_bits;
// };

// struct sdap_hdr {
//     uint8_t qfi : 6;
//     uint8_t reserved : 1;
//     uint8_t DC : 1;
// };

// struct gtp_ext_info {
//     uint16_t seq_num;
//     uint8_t n_pdu;
//     uint8_t next_ext_hdr_type;
// };

// /* We currently only include mandatory part of PDU type 0 */
// struct ran_container_type0 {
// 	uint8_t report_polling : 1;
//     uint8_t dl_flush : 1;
//     uint8_t dl_discard_blocks : 1;
//     uint8_t spare_1 : 1;
//     uint8_t pdu_type : 4;

//     uint8_t retr_flag : 1;
//     uint8_t assist_report_polling_flag : 1;
//     uint8_t user_data_exist_flag : 1;
//     uint8_t report_deliverd : 1;
//     uint8_t req_out_of_seq_report : 1;
//     uint8_t spare : 3;

//     uint32_t nr_seq : 24;
// };

// /* We currently only include mandatory part of PDU type 1 */
// struct ran_container_type1 {
//     uint8_t lost_pkt_report : 1;
//     uint8_t final_frame_ind : 1;
//     uint8_t hd_pdcp_sn_ind : 1; /* Highest Delivered PDCP SN Ind. */
//     uint8_t ht_pdcp_sn_ind : 1; /* Highest Transmitted PDCP SN Ind. */
//     uint8_t pdu_type : 4;

//     uint8_t cause_report : 1;
//     uint8_t delivered_retr_pdcp_sn_ind : 1;
//     uint8_t retr_pdcp_sn_ind : 1;
//     uint8_t data_rate_ind : 1; /* Desired data rate */
//     uint8_t delivered_pdcp_sn_range_ind : 1; /* successfully delivered out of sequence PDCP SN range */
//     uint8_t spare : 3;

//     uint32_t desired_buffer_size;
// };

// static inline uint16_t
// calculate_gtp_ext_hdr_len(uint16_t ext_hdr_len)
// {
// 	return (ext_hdr_len + 0x3) & ~0x3 - 4;
// }

// struct drb_params {
//     uint8_t drb_id;
//     uint16_t ue_id;
//     struct ue_info *ue;
//     uint8_t pdcp_hdr_len; /* 12-bit or 18-bit */
//     //uint8_t pdcp_hdr_type dl_pdcp_hdr_type; /* 12-bit or 18-bit */
//     uint32_t dl_pdcp_sn;
//     uint32_t f1u_ul_teid;
//     uint32_t f1u_dl_teid;
//     uint32_t f1u_dl_ip; /* F1-U UP DL TNL Address in network byte order */
    
//     uint8_t is_active;
//     uint8_t default_qfi;
//     //struct qos_flow_statistics statistics;
//     // uint8_t nb_qos_flow;
//     // struct qos_flow_params *qos_flows;
//     // struct qos_flow_params *qos_flow_ptr[MAX_QOS_FLOW_PER_SESSION];
// };

// struct device_table_entry {
// 	uint8_t device_mac_addr[6];
// 	uint32_t cpe_ip;
// 	uint32_t device_ip;
// 	uint32_t f1u_ul_teid;
//     struct drb_params *drb_context;
// };

// unsigned int hash_mac(uint8_t device_mac_addr[6]);

// int device_table_insert(uint8_t device_mac_addr[6], uint32_t cpe_ip, uint32_t device_ip);
// struct device_table_entry* device_table_get_entry_by_ul_mac(uint32_t hash);

#endif