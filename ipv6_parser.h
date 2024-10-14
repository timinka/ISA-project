#ifndef XADAMC09_ISA_IPV6_PARSER_H
#define XADAMC09_ISA_IPV6_PARSER_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

const size_t next_header_offset = 6;
const size_t ipv6_header_size = 40;
const size_t ipv6_address_size = 16;
const size_t source_ipv6_offset = 8;
static const uint16_t ipv6_type = 0x86DD;
const size_t destination_ipv6_offset = source_ipv6_offset + ipv6_address_size;

std::string parse_ipv6_address(uint8_t* raw_ip);
std::string ipv6_dst (uint8_t* data);
std::string ipv6_src (uint8_t* data);
uint8_t get_next_header_from_ipv6(uint8_t* data);
uint8_t* get_payload_ipv6(uint8_t* data);

#endif