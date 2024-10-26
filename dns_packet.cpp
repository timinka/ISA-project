/***
 * ISA PROJECT
 * @file dns_packet.cpp
 * @author Tímea Adamčíková (xadamc09)
 */

#include <iomanip>
#include <netinet/udp.h>  
#include <netinet/ether.h> 
#include <arpa/inet.h> 
#include <cstring>
#include <pcap.h>
#include "ipv6_parser.h"
#include "ipv4_parser.h"
#include "dns_packet.h"
#include "my_exception.h"

#define DNS_PORT 53

using namespace dns_packet;

struct DNSHeader {
    uint16_t identifier;       
    uint16_t flags;
    uint16_t question_count; 
    uint16_t answer_count;
    uint16_t authority_count; 
    uint16_t additional_count; 
};

// TODO change tmp functions
bool get_qr(uint16_t all_flags) {
    return (all_flags >> 15) & 1;
}

int get_opcode(uint16_t all_flags) {
    return (all_flags >> 11) & 0xF;
}

bool get_aa(uint16_t all_flags) {
    return (all_flags >> 10) & 1; 
}

bool get_tc(uint16_t all_flags) {
    return (all_flags >> 9) & 1;
}

bool get_rd(uint16_t all_flags) {
    return (all_flags >> 8) & 1;
}

bool get_ra(uint16_t all_flags) {
    return (all_flags >> 7) & 1;
}

bool get_ad(uint16_t all_flags) {
    return (all_flags >> 5) & 1;
}

bool get_cd(uint16_t all_flags) {
    return (all_flags >> 4) & 1;
}

int get_rcode(uint16_t all_flags) {
    return all_flags & 0xF;
}

DNSPacket::DNSPacket(const u_char* packet, struct pcap_pkthdr *header, bool verbose) {
    this->verbose = verbose;
    parse(packet, header);
}

uint16_t DNSPacket::get_port_number(uint8_t* raw_port) {
    return ntohs(*reinterpret_cast<uint16_t*>(raw_port));
}

void DNSPacket::parse(const u_char *packet, struct pcap_pkthdr *header) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    uint8_t* ip_header = (uint8_t*)(packet + sizeof(struct ether_header));
    uint16_t type = ntohs(eth_header->ether_type); 
    uint8_t protocol;
    uint8_t* payload;
    
    time_t time = header->ts.tv_sec; 

    std::tm* time_info = std::localtime(&time);
    char buffer[20]; 
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);
    std::string formatted_time(buffer);
    this->timestamp = formatted_time;

    // IPv4 or IPv6
    if (type == ipv6_type) {
        this->src_ip = ipv6_src(ip_header);
        this->dst_ip = ipv6_dst(ip_header);
        protocol = get_next_header_from_ipv6(ip_header);
        payload = get_payload_ipv6(ip_header);
    } else if (type == ipv4_type) {
        this->src_ip = ipv4_src(ip_header);
        this->dst_ip = ipv4_dst(ip_header);
        protocol = get_protocol(ip_header);
        payload = get_payload_ipv4(ip_header);
    }

    // TODO change number for variable
    // Check UDP protocol used
    if (protocol == 0x11) {
        this->protocol = "UDP";
    } else {
        // protocol == 0x06 // TCP
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

    // get flags separetely
    this->qr = get_qr(flags);
    this->query_response = this->qr ? "R" : "Q";
    this->opcode = get_opcode(flags);
    this->aa = get_aa(flags);
    this->tc = get_tc(flags);
    this->rd = get_rd(flags);
    this->ra = get_ra(flags);
    this->ad = get_ad(flags);
    this->cd = get_cd(flags);
    this->rcode = get_rcode(flags);

    if(!this->verbose) { // TODO
        return; //  this is enough information for simple print
    }

    uint8_t* current_pointer = dns_packet_begin + sizeof(DNSHeader); // poiter to start of Question/Answer/Authority/Additional section

    this->sections = std::make_unique<dns_sections::DNSSections>(this->question_num, this->answer_num, this->authority_num, this->additional_num, current_pointer, dns_packet_begin);
}

void DNSPacket::print_simple() {
    std::cout << this->timestamp << " " << this->src_ip << " -> " << this->dst_ip << " (" << this->query_response << " " 
    << this->question_num << "/" << this->answer_num << "/" << this->authority_num << "/" << this->additional_num << ")" << std::endl; 
}

void DNSPacket::print_verbose() {
    std::cout << std::dec << "Timestamp: " << this->timestamp << std::endl;
    std::cout << "SrcIP: " << this->src_ip << std::endl;
    std::cout << "DstIP: " << this->dst_ip << std::endl;
    std::cout << "SrcPort: " << this->protocol << "/" << this->src_port << std::endl;
    std::cout << "DstPort: " <<  this->protocol << "/" << this->dst_port << std::endl;
    std::cout << "Identifier: 0x" << std::setfill ('0') << std::setw(4) << std::hex << this->identifier << std::endl;
    std::cout << "Flags: QR=" << std::dec << this->qr << ", OPCODE=" << this->opcode << ", AA=" << this->aa << ", TC=" << this->tc 
    << ", RD=" << this->rd << ", RA=" << this->ra << ", AD=" << this->ra << ", CD=" << this->cd << ", RCODE=" << this->rcode << std::endl << std::endl;  

    // print sections
    if (this->sections->question_num != 0) {
        std::cout << "[Question Section]" << std::endl;

        for (const auto& question : this->sections->questions) {
            std::cout << question.qname << " " << question.qclass << " " << question.qtype << std::endl;
        }

        std::cout << std::endl;
    }    

    if (this->sections->answer_num != 0) {
        std::cout << "[Answer Section]" << std::endl;

        for (const auto& answer : this->sections->answers) {
            std::visit(PrintVisitor{}, answer);
        }

        std::cout << std::endl;
    }

    if (this->sections->authority_num != 0) {
        std::cout << "[Authority Section]" << std::endl;

        for (const auto& authority : this->sections->authorities) {
            std::visit(PrintVisitor{}, authority);
        }

        std::cout << std::endl;
    }

    if (this->sections->additional_num != 0) {
        std::cout << "[Additional Section]" << std::endl;

        for (const auto& additional : this->sections->additionals) {
            std::visit(PrintVisitor{}, additional);
        }
    }

    std::cout << "====================" << std::endl;
}
