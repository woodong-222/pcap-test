#pragma once

#define ETHERNET_MAC_SIZE 6
#define ETHERNET_SIZE 14
#define IPV4_SIZE 20
#define TCP_SIZE 20
#define ETHERTYPE 12
#define PROTOCOL 23
#define IPV4 0x0800
#define TCP 6

typedef struct {
    char* dev_;
} Param;

typedef struct
{
    u_int8_t    destination_mac_address[ETHERNET_MAC_SIZE];
    u_int8_t    source_mac_address[ETHERNET_MAC_SIZE];
    u_int16_t   ether_type;
} EthernetHeader;

typedef struct
{
    u_int8_t    version:4,
                ihl:4;
    u_int8_t    dscp:6,
                ecn:2;
    u_int16_t   total_length;
    u_int16_t    identification;
    u_int16_t   flags:3,
                fragment_offset:13;
    u_int8_t    time_to_live;
    u_int8_t    protocol;
    u_int16_t   header_checksum;
    u_int32_t   source_address;
    u_int32_t   destination_address;
} Ipv4Header;

typedef struct
{
    u_int16_t source_port;
    u_int16_t destination_port;
    u_int32_t sequence_number;
    u_int32_t acknowledgement_number;
    u_int8_t    data_offset:4,
                reserved:4;
    u_int8_t    cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent_pointer;
} TcpHeader;
