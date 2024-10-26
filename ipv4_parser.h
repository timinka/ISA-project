/***
 * ISA PROJECT
 * @file ipv4_parser.h
 * @author Tímea Adamčíková (xadamc09)
 */

#ifndef XADAMC09_ISA_IPV4_PARSER_H
#define XADAMC09_ISA_IPV4_PARSER_H

const size_t protocol_offset = 9;
const size_t ipv4_address_size = 4;
const size_t source_ipv4_offset = 12;
const size_t destination_ipv4_offset = source_ipv4_offset + ipv4_address_size;
static const uint16_t ipv4_type = 0x0800;

std::string parse_ipv4_address(uint8_t* raw_ip);
std::string ipv4_dst (uint8_t* data);
std::string ipv4_src (uint8_t* data);
uint8_t get_protocol(uint8_t* data);
uint8_t* get_payload_ipv4(uint8_t* data);

#endif