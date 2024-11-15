/***
 * ISA PROJECT
 * @file arg_parser.h
 * @author Tímea Adamčíková (xadamc09)
 */

#ifndef XADAMC09_ISA_ARG_PARSER
#define XADAMC09_ISA_ARG_PARSER
#include <iostream>


/**
 * @brief Representation of arguments from command line
 * 
 * - `use_interface` - Flag if program should listen on live interface
 * - `use_file` - Flag if program should open file to read packets
 * - `interface` - Network interface name
 * - `pcap_file` - PCAP file name
 * - `verobose` - If true print more detailed output 
 * - `domains_file` - File name for domain names output
 * - `d_mode` - Flag for domain name output
 * - `translations_file` - File name for translations ouput
 * - `t_mode` - Flag for translation output
 */
struct arguments {
    bool use_interface = false;
    bool use_file = false;
    std::string interface;
    std::string pcap_file;
    bool verbose = false;
    std::string domains_file;
    bool d_mode = false;
    std::string translations_file;
    bool t_mode = false;
};


namespace arg_parser {
    /**
     * @brief Parse command line arguments and provide arguments in `arguments` structure 
     * 
     * @param argc Number of command line arguments
     * @param argv Array of command line arguments
     * @param args Reference to `arguments` structure where options will be stored
     * @throw ArgParserError when unsupported argument appear, or when there are missing mandatory arguments
     */
    void parse_arguments(int argc, char **argv, arguments& args);


    /**
     * @brief Print help to standard output
     */
    void print_help();
}


#endif