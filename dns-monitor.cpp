/***
 * ISA PROJECT
 * @file dns-monitor.cpp
 * @author Tímea Adamčíková (xadamc09)
 */

#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <pcap/pcap.h>
#include <csignal>
#include "dns_packet.h"
#include "my_exception.h"

volatile sig_atomic_t stop = 0;
pcap_t *handle;

void signal_handler(int signal_num) { // TODO
    stop = 1;
    if (handle) {
        pcap_breakloop(handle);
    }
}

int handle_setup(pcap_t *handle, char *ERRBUF) {
    if (handle == nullptr) {
        std::cerr << "Error opening file: " << ERRBUF << std::endl;
        throw HandleSetUpErr();
    }

    int dtl = pcap_datalink(handle);
    if (dtl != DLT_EN10MB && dtl != DLT_LINUX_SLL) {
        std::cerr << "Unsupported datalink" << std::endl;
        pcap_close(handle);
        throw HandleSetUpErr();
    }

    struct bpf_program fp;
    // filter for only DNS communication
    const char filter_exp[] = "port 53"; 
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        throw HandleSetUpErr();
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        throw HandleSetUpErr();
    }

    pcap_freecode(&fp);
    return dtl;
}

int main (int argc, char **argv) {
    char opt;
    bool use_interface = false;
    bool use_file = false;
    std::string interface;
    char* pcap_file;
    bool verbose = false;
    std::string domains_file;
    bool d_mode = false;
    std::string translations_file;
    bool t_mode = false;

    opterr = 0; // getopt without error
    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch (opt) {
            case 'i':
                if (use_file || use_interface) {
                    std::cerr << "Too many arguments" << std::endl;
                    return 1;
                }
                use_interface = true;
                interface = optarg;
                break;
            case 'p':
                if (use_file || use_interface) {
                    std::cerr << "Too many arguments" << std::endl;
                    return 1;
                }
                use_file = true;
                pcap_file = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'd':
                d_mode = true;
                domains_file = optarg;
                break;
            case 't':
                t_mode = true;
                translations_file = optarg;
                break;
            default:
                std::cerr << "Unsuported argument" << std::endl;
                return 1;
        }
    }

    char ERRBUF[PCAP_ERRBUF_SIZE];


    //
    if (use_file) {
        handle = pcap_open_offline(pcap_file, ERRBUF);
    } else if (use_interface) {
        // define signals
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
        std::signal(SIGQUIT, signal_handler);

        // TODO
        if ((handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, ERRBUF)) == nullptr) {
            handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 0, ERRBUF);
        }

    } else {
        std::cerr << "Missing arguments" << std::endl;
        return 1;
    }

    int dtl;
    try {
        dtl = handle_setup(handle, ERRBUF);
    } catch (const HandleSetUpErr& e) {
        return 1;
    }

    struct pcap_pkthdr *header;  
    const u_char *packet; 

    while (pcap_next_ex(handle, &header, &packet) >= 0 && !stop) {
        try {
            dns_packet::DNSPacket my_instance(packet, header, dtl, verbose, t_mode, translations_file, d_mode, domains_file);
            if (verbose) {
                my_instance.print_verbose();
            } else {
                my_instance.print_simple();
            }
        } catch (const IgnorePacket& e) {
            continue;
        }
    }


    pcap_close(handle);
    return 0;
}