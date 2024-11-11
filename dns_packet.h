/***
 * ISA PROJECT
 * @file dns_packet.h
 * @author Tímea Adamčíková (xadamc09)
 */

#ifndef XADAMC09_ISA_DNS_PACKET
#define XADAMC09_ISA_DNS_PACKET

#include <string>
#include <vector>

#include "dns_sections.h"

namespace dns_packet {
    /**
     * @brief Class representing DNS packet
     */
    class DNSPacket {
        private:
            /**
             * @brief Timestamp when packet was captured
             */
            std::string timestamp;

            /**
             * @brief Source IP address
             */
            std::string src_ip;
            
            /**
             * @brief Destination IP address
             */
            std::string dst_ip;

            /**
             * @brief Used network protocol
             */
            std::string protocol;

            /**
             * @brief Source port number
             */
            uint16_t src_port;
            
            /**
             * @brief Destination port number
             */
            uint16_t dst_port;

            /**
             * @brief DNS packet identifier
             */
            uint16_t identifier;

            /**
             * @brief DNS packet flags. 
             * 
             * qr - Query/Response, 
             * aa - Authoritative Answer, 
             * tc- Truncation, 
             * rd - Recursion Desired, 
             * ra - Recursion Available, 
             * ad - Authentic Data, 
             * cd - Checking Disabled
             */
            bool qr, aa, tc, rd, ra, ad, cd;

            /**
             * @brief DNS operation code (OPCODE) and response code (RCODE, indicating error/status)
             */
            int opcode, rcode;

            /**
             * @brief Datalink identifier (ethernet or linux cooked)
             */
            int datalink;

            /**
             * @brief Number of records in section
             */
            int question_num, answer_num, authority_num, additional_num;
            
            /**
             * @brief Query or response in string format
             */
            std::string query_response;

            /**
             * @brief Parse all required information from packet
             * 
             * @param packet Pointer to packet data
             * @param header Pointer to packet header to extract timestamp
             * @throw IgnorePacket when internet protocol is not IPv4 or IPv6, or when trasport protocol is not UDP
             */
            void parse(const u_char *packet, struct pcap_pkthdr *header);

            /**
             * @brief Extract port number from raw data
             * 
             * @param raw_port Pointer to raw port data
             * @return Port number as uint16_t
             */
            uint16_t get_port_number(uint8_t* raw_port);

            /**
             * @brief Pointer to DNSSections class holding information about sections 
             */
            std::unique_ptr<dns_sections::DNSSections> sections;

            /**
             * @brief Flags for translations and domain name modes
             */
            bool t_mode, d_mode;

            /**
             * @brief Names of files to write translations and domain names
             */
            std::string translations_file, domains_file;

        public:
            /**
             * @brief Constructor for DNSPacket
             * 
             * @param packet Pointer to packet
             * @param header Pointer to packet header
             * @param dtl Datalink type
             * @param t_mode Flag for translation mode
             * @param translations_file Name of file for storing translations (A and AAAA records)
             * @param d_mode Flag for domain name mode
             * @param domains_file Name of file for storing domain names
             */
            DNSPacket(const u_char *packet, struct pcap_pkthdr *header, int dtl,
                        bool t_mode, std::string translations_file, bool d_mode, std::string domains_file);

            /**
             * @brief Print extracted packet information to output 
             */
            void print_simple();

            /**
             * @brief Print extracted packet information to output with verbose mode 
             */
            void print_verbose();
    };
}

#endif