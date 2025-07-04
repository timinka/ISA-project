/***
 * ISA PROJECT
 * @file ipv4_parser.h
 * @author Tímea Adamčíková (xadamc09)
 */

#ifndef XADAMC09_ISA_IPV4_PARSER_H
#define XADAMC09_ISA_IPV4_PARSER_H


namespace ipv4_parser {
    const size_t protocol_offset = 9;
    const size_t ipv4_address_size = 4;
    const size_t source_ipv4_offset = 12;
    const size_t destination_ipv4_offset = source_ipv4_offset + ipv4_address_size;
    static const uint16_t ipv4_type = 0x0800;

    /**
     * @brief Convert raw IPv4 address to string representation
     * 
     * @param raw_ip Pointer to raw IPv4 address
     * @return String containing IPv4 address or empty string if it fails
     */
    std::string parse_ipv4_address(uint8_t* raw_ip);


    /**
     * @brief Find and parse destination IPv4 address from data buffer
     * 
     * @param data Pointer to data buffer
     * @return String containing destination IPv4 address
     */
    std::string ipv4_dst(uint8_t* data);


    /**
     * @brief Find and parse source IPv4 address from data buffer
     * 
     * @param data Pointer to data buffer
     * @return String containing source IPv4 address
     */
    std::string ipv4_src(uint8_t* data);


    /**
     * @brief Extract higher-level protocol from IPv4 packet
     * 
     * @param data Pointer to data buffer
     * @return Protocol field
     */
    uint8_t get_protocol(uint8_t* data);


    /**
     * @brief Calculate the starting address of IPv4 packet payload
     * 
     * @param data Pointer to data buffer
     * @return Pointer to the beginning of the payload
     */
    uint8_t* get_payload_ipv4(uint8_t* data);
}

#endif