/***
 * ISA PROJECT
 * @file ipv6_parser.h
 * @author Tímea Adamčíková (xadamc09)
 */

#ifndef XADAMC09_ISA_IPV6_PARSER_H
#define XADAMC09_ISA_IPV6_PARSER_H


namespace ipv6_parser {
    const size_t next_header_offset = 6;
    const size_t ipv6_header_size = 40;
    const size_t ipv6_address_size = 16;
    const size_t source_ipv6_offset = 8;
    static const uint16_t ipv6_type = 0x86DD;
    const size_t destination_ipv6_offset = source_ipv6_offset + ipv6_address_size;

    /**
     * @brief Convert raw IPv6 address to string representation
     * 
     * @param raw_ip Pointer to raw IPv6 address
     * @return String containing IPv6 address or empty string if it fails
     */
    std::string parse_ipv6_address(uint8_t* raw_ip);


    /**
     * @brief Find and parse destination IPv6 address from data buffer
     * 
     * @param data Pointer to data buffer
     * @return String containing destination IPv6 address
     */
    std::string ipv6_dst (uint8_t* data);


    /**
     * @brief Find and parse source IPv6 address from data buffer
     * 
     * @param data Pointer to data buffer
     * @return String containing source IPv6 address
     */
    std::string ipv6_src (uint8_t* data);


    /**
     * @brief Extract higher-level protocol from IPv6 packet
     * 
     * @param data Pointer to data buffer
     * @return Protocol field
     */
    uint8_t get_next_header_from_ipv6(uint8_t* data);


    /**
     * @brief Get the starting address of IPv6 packet payload
     * 
     * @param data Pointer to data buffer
     * @return Pointer to the beginning of the payload
     */
    uint8_t* get_payload_ipv6(uint8_t* data);
}

#endif