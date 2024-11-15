/***
 * ISA PROJECT
 * @file arg_parser.cpp
 * @author Tímea Adamčíková (xadamc09)
 */

#include "arg_parser.h"
#include "my_exception.h"
#include <unistd.h>

void arg_parser::print_help() {
    std::cout << "./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]" << std::endl
        << "-i <interface> - name of interface, where will program listen, or" << std::endl
        << "-p <pcapfile> - name of PCAP file, which will program analyse;" << std::endl
        << "-v - mode `verbose`: complete listing of DNS messages details;" << std::endl
        << "-d <domainsfile> - file name for domain names;" << std::endl
        << "-t <translationsfile> - file name for domain names to IP translations." << std::endl;
}


void arg_parser::parse_arguments(int argc, char **argv, arguments& args) {
    char opt;
    
    opterr = 0; // getopt without error
    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch (opt) {
            case 'i':
                if (args.use_file || args.use_interface) {
                    std::cerr << "Too many arguments" << std::endl;
                    print_help();
                    throw ArgParserError();
                }
                args.use_interface = true;
                args.interface = optarg;
                break;
            case 'p':
                if (args.use_file || args.use_interface) {
                    std::cerr << "Too many arguments" << std::endl;
                    print_help();
                    throw ArgParserError();
                }
                args.use_file = true;
                args.pcap_file = optarg;
                break;
            case 'v':
                args.verbose = true;
                break;
            case 'd':
                args.d_mode = true;
                args.domains_file = optarg;
                break;
            case 't':
                args.t_mode = true;
                args.translations_file = optarg;
                break;
            default:
                std::cerr << "Unsuported argument" << std::endl;
                print_help();
                throw ArgParserError();
        }
    }

    if (!args.use_file && !args.use_interface) { // one of them must be defined
        std::cerr << "Missing arguments!" << std::endl;
        throw ArgParserError();
    }
}