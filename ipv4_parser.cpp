/***
 * ISA PROJECT
 * @file ipv4_parser.cpp
 * @author Tímea Adamčíková (xadamc09)
 */

#include <sys/socket.h>
#include <stdint.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ipv4_parser.h"

std::string ipv4_parser::parse_ipv4_address(uint8_t* raw_ip) {
    char ip[INET_ADDRSTRLEN];
    const char* result = inet_ntop(AF_INET, raw_ip, ip, sizeof(ip));
    return std::string(result == nullptr ? "" : result);
}

std::string ipv4_parser::ipv4_dst (uint8_t* data) {
    return ipv4_parser::parse_ipv4_address(data + destination_ipv4_offset);
}

std::string ipv4_parser::ipv4_src (uint8_t* data) {
    return ipv4_parser::parse_ipv4_address(data + source_ipv4_offset);
}

uint8_t ipv4_parser::get_protocol(uint8_t* data) {
    return *(data + protocol_offset);
}

uint8_t* ipv4_parser::get_payload_ipv4(uint8_t* data) {
    uint8_t ihl = (*data) & 0xF;
    return data + 4 * ihl;
}
