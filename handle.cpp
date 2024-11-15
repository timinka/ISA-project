/***
 * ISA PROJECT
 * @file handle.cpp
 * @author Tímea Adamčíková (xadamc09)
 */
#include "handle.h"
#include "my_exception.h"
#include "dns_packet.h"
#include <fstream>
#include <csignal>

// define handle
pcap_t *handler::handle = nullptr;


void handler::signal_handler(int signal_num) {
    if (handle) {
        pcap_breakloop(handler::handle);
    }
}


void handler::define_handle(arguments args) {
    char ERRBUF[PCAP_ERRBUF_SIZE];

    if (args.use_file) {
        handler::handle = pcap_open_offline(args.pcap_file.c_str(), ERRBUF);
    } else { // using interface
        // define signals
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
        std::signal(SIGQUIT, signal_handler);

        // TODO
        if ((handler::handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 1, 1, ERRBUF)) == nullptr) {
            handler::handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 1, 0, ERRBUF);
        }

    }

    int dtl; // datalink type
    try {
        dtl = handle_setup(handler::handle, ERRBUF);
    } catch (const HandleSetUpErr& e) {
        throw HandleSetUpErr();
    }

    struct pcap_pkthdr *header;  
    const u_char *packet; 

    if (args.d_mode && !prepare_file(args.domains_file)) {
        pcap_close(handler::handle);
        throw HandleSetUpErr();
    }

    if (args.t_mode && !prepare_file(args.translations_file)) {
        pcap_close(handler::handle);
        throw HandleSetUpErr();
    }

    while (pcap_next_ex(handler::handle, &header, &packet) >= 0) {
        try {
            dns_packet::DNSPacket my_instance(packet, header, dtl, args.t_mode, args.translations_file, args.d_mode, args.domains_file);
            if (args.verbose) {
                my_instance.print_verbose();
            } else {
                my_instance.print_simple();
            }
        } catch (const IgnorePacket& e) {
            continue;
        }
    }

    pcap_close(handler::handle);
}


int handler::handle_setup(pcap_t *handle, char *ERRBUF) {
    if (handle == nullptr) {
        std::cerr << "Error: " << ERRBUF << std::endl;
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


bool handler::prepare_file(std::string file) {
    // prepare empty file or create new file
    std::ofstream d_file(file, std::ios::trunc);
    if (!d_file) {
        std::cerr << "Cannot open " << file << "." << std::endl;
        return false;
    }
    d_file.close();
    return true;
}