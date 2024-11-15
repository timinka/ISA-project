/***
 * ISA PROJECT
 * @file ipv6_parser.cpp
 * @author Tímea Adamčíková (xadamc09)
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

#include "ipv6_parser.h"

std::string ipv6_parser::parse_ipv6_address(uint8_t* raw_ip) {
    char ip[INET6_ADDRSTRLEN];
    const char* result = inet_ntop(AF_INET6, raw_ip, ip, sizeof(ip));
    return std::string(result == nullptr? "" : result);
}

std::string ipv6_parser::ipv6_dst(uint8_t* data) {
    return ipv6_parser::parse_ipv6_address(data + destination_ipv6_offset);
}

std::string ipv6_parser::ipv6_src(uint8_t* data) {
    return ipv6_parser::parse_ipv6_address(data + source_ipv6_offset);
}

uint8_t ipv6_parser::get_next_header_from_ipv6(uint8_t* data) {
    return *(data + next_header_offset);
}

uint8_t* ipv6_parser::get_payload_ipv6(uint8_t* data) {
    return data + ipv6_header_size;
}