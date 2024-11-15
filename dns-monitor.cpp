/***
 * ISA PROJECT
 * @file dns-monitor.cpp
 * @author Tímea Adamčíková (xadamc09)
 */

#include <stdio.h>

#include "dns_packet.h"
#include "my_exception.h"
#include "arg_parser.h"
#include "handle.h"


int main (int argc, char **argv) {
    arguments args;

    try {
        arg_parser::parse_arguments(argc, argv, args);
    } catch (const ArgParserError& e) {
        return 1;
    }

    try {
        handler::define_handle(args);
    } catch (const HandleSetUpErr& e) {
        return 1;
    }
    
    return 0;
}