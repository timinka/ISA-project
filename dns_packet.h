#ifndef XADAMC09_ISA_DNS_PACKET
#define XADAMC09_ISA_DNS_PACKET

#include <ctime> 
#include <string>
#include <netinet/udp.h>  
#include <netinet/ether.h> 
#include <arpa/inet.h> 
#include <pcap.h>
#include <cstring>
#include <iomanip>
#include <bitset> // tmp

#include "ipv6_parser.h"
#include "ipv4_parser.h"

namespace dns_packet {
    class DNSPacket {
        private:
            std::string timestamp, src_ip, dst_ip, protocol;
            uint16_t src_port;
            uint16_t dst_port;
            uint16_t identifier;
            bool qr, aa, tc, rd, ra, ad, cd;
            int opcode, rcode;
            int question_num, answer_num, authority_num, additional_num;
            std::string query_response, question_section, answer_section, authority_section, additional_section;
            void parse(const u_char *packet, struct pcap_pkthdr *header);
            uint16_t get_port_number(uint8_t* raw_port);

        public:
            DNSPacket(const u_char *packet, struct pcap_pkthdr *header);
            void print_simple();
            void print_verbose();
    };
}

#endif