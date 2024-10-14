#ifndef XADAMC09_ISA_DNS_PACKET
#define XADAMC09_ISA_DNS_PACKET

#include <ctime> 
#include <string>
#include <netinet/udp.h>  
#include <netinet/ether.h> 
#include <arpa/inet.h> 
#include <pcap.h>

#include "ipv6_parser.h"
#include "ipv4_parser.h"

namespace dns_packet {
    class DNSPacket {
        private:
            bool verbose;
            std::string timestamp;
            std::string src_ip;
            std::string dst_ip;
            std::string protocol;
            uint16_t src_port;
            uint16_t dst_port;
            std::string identifier;
            bool qr, opcode, aa, tc, rd, ra, ad, cd, rcode;
            std::string question_section;
            std::string answer_section;
            std::string authority_section;
            std::string additional_section;
            // void print_verbose();
            void parse(const u_char *packet, struct pcap_pkthdr *header);
            uint16_t get_port_number(uint8_t* raw_port);

        public:
            DNSPacket(bool verbose, const u_char *packet, struct pcap_pkthdr *header);
            void print_simple();
    };
}

#endif