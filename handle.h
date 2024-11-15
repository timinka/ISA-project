/***
 * ISA PROJECT
 * @file handle.h
 * @author Tímea Adamčíková (xadamc09)
 */

#ifndef XADAMC09_ISA_HANDLE
#define XADAMC09_ISA_HANDLE
#include "arg_parser.h"
#include <pcap.h>


namespace handler {
    // pcap handle
    extern pcap_t *handle;

    /**
     * @brief Initialize and set up pcap handle for packet capture (from pcap file or from interface)
     * It additionally sets up singnals for live interface capturing and prepares files for text output.
     * 
     * @param args Structure of arguments from command line
     * 
     * @throw HandleSetUpError if handle or file preparation fails
     */
    void define_handle(arguments args);


    /**
     * @brief Set up filter to capture only DNS communication (port 53)
     * 
     * @param handle Apply filter to this handle
     * @param ERRBUF Error buffer to print error 
     * @return Datalink type if it is supported
     * @throw HandleSetUpError when filter fails to apply or when unsupported datalink occures
     */
    int handle_setup(pcap_t *handle, char *ERRBUF);

    /**
     * @brief Prepare empty file or create new file 
     * 
     * @param file File name to be created
     * @return True if file can be created/opened, False otherwise
     */
    bool prepare_file(std::string file);

    /**
     * @brief Manage signals
     * 
     * @param signal_num Identifier of singal incomming
     */
    void signal_handler(int signal_num);
}

#endif