#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <pcap/pcap.h>
#include "dns_packet.h"

using namespace std;

// void print_packet(const u_char *packet, struct pcap_pkthdr packet_header) {
//     std::cout << "Packet length: " << packet_header.len << " bytes\n";
//     std::cout << "Captured length: " << packet_header.caplen << " bytes\n";
//     std::cout << "Timestamp: " << packet_header.ts.tv_sec << "." << packet_header.ts.tv_usec << "\n";

//     // Print the packet content in hex format
//     std::cout << "Packet content (hex):\n";
//     for (u_int i = 0; i < packet_header.caplen; i++) {
//         std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(packet[i]);
//         if ((i + 1) % 16 == 0)
//             std::cout << "\n";  // New line every 16 bytes for readability
//         else
//             std::cout << " ";
//     }

//     std::cout << "\n\n";
// }



// void parse_ip(const u_char *packet) {
//     struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
//     char src_ip[INET_ADDRSTRLEN];
//     char dst_ip[INET_ADDRSTRLEN];

//     // Convert IP addresses to human-readable form
//     inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
//     inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

//     std::cout << "IP Header:\n";
//     std::cout << "  Source IP: " << src_ip << "\n";
//     std::cout << "  Destination IP: " << dst_ip << "\n";
//     std::cout << "  Protocol: " << static_cast<int>(ip_header->ip_p) << "\n";  // IP protocol (e.g., TCP=6, UDP=17)

//     if (ip_header->ip_p == IPPROTO_TCP) {
//         std::cout << "  Protocol: TCP\n";
//     } else if (ip_header->ip_p == IPPROTO_UDP) {
//         std::cout << "  Protocol: UDP\n";
//     }
// }

int main (int argc, char **argv) {
    char opt;
    bool use_interface = false;
    bool use_file = false;
    string interface;
    char* pcap_file;
    bool verbose = false;
    string domains_file;
    string translations_file;

    opterr = 0; // getopt without error
    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch (opt) {
            case 'i':
                if (use_file || use_interface) {
                    cerr << "Too many arguments" << endl;
                    return 1;
                }
                use_interface = true;
                interface = optarg;
                break;
            case 'p':
                if (use_file || use_interface) {
                    cerr << "Too many arguments" << endl;
                    return 1;
                }
                use_file = true;
                pcap_file = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'd':
                domains_file = optarg;
                break;
            case 't':
                translations_file = optarg;
                break;
            default:
                cerr << "Unsuported argument" << endl;
                return 1;
        }
    }

    if (use_file) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_offline(pcap_file, errbuf);

        if (handle == nullptr) {
            cerr << "Error opening file: " << errbuf << endl;
            return 1;
        }

        struct bpf_program fp;
        // filter for only DNS communication
        const char filter_exp[] = "port 53"; 
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            cerr << "Error compiling filter: " << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            return 1;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            cerr << "Error setting filter: " << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            return 1;
        }

        struct pcap_pkthdr *header;  
        const u_char *packet; 

        while (pcap_next_ex(handle, &header, &packet) >= 0) {
            // try:
                dns_packet::DNSPacket my_instance(packet, header, verbose);
                if (verbose) {
                    my_instance.print_verbose();
                } else {
                    my_instance.print_simple();
                }
            // catch ...
        }

        pcap_close(handle);
    } else if (use_interface) {
        // TODO
    } else {
        cerr << "Missing arguments" << endl;
        return 1;
    }

    return 0;
}