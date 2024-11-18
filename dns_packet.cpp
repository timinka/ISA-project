/***
 * ISA PROJECT
 * @file dns_packet.cpp
 * @author Tímea Adamčíková (xadamc09)
 */

#include <iomanip>
#include <netinet/udp.h>
#include <net/ethernet.h> 
#include <arpa/inet.h> 
#include <pcap.h>
#include "ipv6_parser.h"
#include "ipv4_parser.h"
#include "dns_packet.h"
#include "my_exception.h"

#define UDP_PROTOCOL 0x11
#define DNS_PORT 53

using namespace dns_packet;


DNSPacket::DNSPacket(const u_char *packet, struct pcap_pkthdr *header, int dtl, 
                        bool t_mode, std::string translations_file, bool d_mode, std::string domains_file) {
    this->t_mode = t_mode;
    this->translations_file = translations_file;
    this->d_mode = d_mode;
    this->domains_file = domains_file;
    this->datalink = dtl;
    parse(packet, header);
}


uint16_t DNSPacket::get_port_number(uint8_t* raw_port) {
    return ntohs(*reinterpret_cast<uint16_t*>(raw_port));
}


void DNSPacket::parse(const u_char *packet, struct pcap_pkthdr *header) {
    uint8_t* ip_header;
    uint16_t protocol_type;

    if (this->datalink == DLT_EN10MB) { // ethernet
        struct ether_header *eth_header = (struct ether_header *)packet;
        ip_header = (uint8_t*)(packet + sizeof(struct ether_header));
        protocol_type = ntohs(eth_header->ether_type); 
    } else { // linux cooked
        packet += 12;
        uint16_t *type = (uint16_t*)packet;
        ip_header = (uint8_t*)(packet + 2);
        protocol_type = ntohs(*type);
    }
    
    time_t time = header->ts.tv_sec; 

    std::tm* time_info = std::localtime(&time);
    char buffer[20]; 
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);
    std::string formatted_time(buffer);
    this->timestamp = formatted_time;

    uint8_t protocol;
    uint8_t* payload;
    // IPv4 or IPv6
    if (protocol_type == ipv6_parser::ipv6_type) {
        this->src_ip = ipv6_parser::ipv6_src(ip_header);
        this->dst_ip = ipv6_parser::ipv6_dst(ip_header);
        protocol = ipv6_parser::get_next_header_from_ipv6(ip_header);
        payload = ipv6_parser::get_payload_ipv6(ip_header);
    } else if (protocol_type == ipv4_parser::ipv4_type) {
        this->src_ip = ipv4_parser::ipv4_src(ip_header);
        this->dst_ip = ipv4_parser::ipv4_dst(ip_header);
        protocol = ipv4_parser::get_protocol(ip_header);
        payload = ipv4_parser::get_payload_ipv4(ip_header);
    } else {
        throw IgnorePacket();
    }

    // Check UDP protocol used
    if (protocol == UDP_PROTOCOL) {
        this->protocol = "UDP";
    } else {
        throw IgnorePacket();
    }

    this->src_port = this->get_port_number(payload);
    this->dst_port = this->get_port_number(payload + 2);
    
    DNSHeader *dns_header;
    if (src_port != DNS_PORT && dst_port != DNS_PORT) {
        // not a DNS packet
        throw IgnorePacket();
    }

    uint8_t* dns_packet_begin = payload + 8;
    dns_header = (DNSHeader *)(dns_packet_begin);
    // info from dns header
    this->question_num = ntohs(dns_header->question_count);
    this->answer_num = ntohs(dns_header->answer_count);
    this->authority_num = ntohs(dns_header->authority_count);
    this->additional_num = ntohs(dns_header->additional_count);
    this->identifier = ntohs(dns_header->identifier);

    uint16_t flags = ntohs(dns_header->flags);
    this->flags = std::make_unique<dns_flags::DNSFlags>(flags);

    uint8_t* current_pointer = dns_packet_begin + sizeof(DNSHeader); // poiter to start of Question/Answer/Authority/Additional section

    this->sections = std::make_unique<dns_sections::DNSSections>(this->question_num, this->answer_num, this->authority_num, this->additional_num, current_pointer, 
                            dns_packet_begin, this->t_mode, this->translations_file, this->d_mode, this->domains_file);
}

void DNSPacket::print_simple() {
    std::cout << this->timestamp << " " << this->src_ip << " -> " << this->dst_ip << " (" << this->flags->query_response << " " 
    << this->question_num << "/" << this->answer_num << "/" << this->authority_num << "/" << this->additional_num << ")" << "\n"; 
}

void DNSPacket::print_verbose() {
    std::cout << std::dec << "Timestamp: " << this->timestamp << "\n";
    std::cout << "SrcIP: " << this->src_ip << "\n";
    std::cout << "DstIP: " << this->dst_ip << "\n";
    std::cout << "SrcPort: " << this->protocol << "/" << this->src_port << "\n";
    std::cout << "DstPort: " <<  this->protocol << "/" << this->dst_port << "\n";
    std::cout << "Identifier: 0x" << std::setfill ('0') << std::setw(4) << std::hex << std::uppercase << this->identifier << std::nouppercase << "\n";
    std::cout << "Flags: QR=" << std::dec << this->flags->qr << ", OPCODE=" << this->flags->opcode << ", AA=" << this->flags->aa << ", TC=" << this->flags->tc 
    << ", RD=" << this->flags->rd << ", RA=" << this->flags->ra << ", AD=" << this->flags->ad << ", CD=" << this->flags->cd << ", RCODE=" << this->flags->rcode << "\n";  

    // print sections
    if (this->sections->question_num != 0) {
        std::cout << "\n" << "[Question Section]" << "\n";

        for (const auto& question : this->sections->questions) {
            std::cout << question.qname << " " << question.qclass << " " << question.qtype << "\n";
        }
    }    

    if (this->sections->answer_num != 0) {
        std::cout << "\n" << "[Answer Section]" << "\n";

        for (const auto& answer : this->sections->answers) {
            std::visit(PrintVisitor{}, answer);
        }
    }

    if (this->sections->authority_num != 0) {
        std::cout << "\n" << "[Authority Section]" << "\n";

        for (const auto& authority : this->sections->authorities) {
            std::visit(PrintVisitor{}, authority);
        }
    }

    if (this->sections->additional_num != 0) {
        std::cout << "\n" << "[Additional Section]" << "\n";

        for (const auto& additional : this->sections->additionals) {
            std::visit(PrintVisitor{}, additional);
        }
    }

    std::cout << "====================" << "\n";
}
