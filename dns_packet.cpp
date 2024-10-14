#include "dns_packet.h"
using namespace dns_packet;

DNSPacket::DNSPacket(bool verbose, const u_char* packet, struct pcap_pkthdr *header) {
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

    std::tm* time_info = std::gmtime(&time); // TODO localtime?
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
    // TCP or UDP protocol used
    if (protocol == 0x06) {
        this->protocol = "TCP";
    } else if (protocol == 0x11) {
        this->protocol = "UDP";
    }

    this->src_port = this->get_port_number(payload);
    this->dst_port = this->get_port_number(payload + 2);
}

void DNSPacket::print_simple() {
    std::cout << "Timestamp: " << this->timestamp << std::endl;
    std::cout << "Source ip: " << this->src_ip << std::endl;
    std::cout << "Destination ip: " << this->dst_ip << std::endl;
    std::cout << "Protocol: " << this->protocol << std::endl;
    std::cout << "Source port: " << this->src_port << std::endl;
    std::cout << "Destination port: " << this->dst_port << std::endl;
    std::cout << "\n\n";
}
