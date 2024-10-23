#ifndef XADAMC09_ISA_DNS_PACKET
#define XADAMC09_ISA_DNS_PACKET

#include <string>
#include <vector>

#include "dns_sections.h"

namespace dns_packet {
    class DNSPacket {
        private:
            std::string timestamp, src_ip, dst_ip, protocol;
            uint16_t src_port;
            uint16_t dst_port;
            uint16_t identifier;
            bool qr, aa, tc, rd, ra, ad, cd, verbose;
            int opcode, rcode;
            int question_num, answer_num, authority_num, additional_num;
            std::string query_response, question_section, answer_section, authority_section, additional_section;
            void parse(const u_char *packet, struct pcap_pkthdr *header);
            uint16_t get_port_number(uint8_t* raw_port);
            std::unique_ptr<dns_sections::DNSSections> sections;

        public:
            DNSPacket(const u_char *packet, struct pcap_pkthdr *header, bool verbose);
            void print_simple();
            void print_verbose();
    };
}

#endif