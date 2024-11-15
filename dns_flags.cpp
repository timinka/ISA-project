/***
 * ISA PROJECT
 * @file dns_flags.cpp
 * @author Tímea Adamčíková (xadamc09)
 */

#include "dns_flags.h"
#include <iostream>

using namespace dns_flags;

DNSFlags::DNSFlags(uint16_t flags) {
    this->flags = flags;

    std::cout << "FLAGS =================" << flags << std::endl;

    // get flags separetely
    this->qr = get_qr();
    this->query_response = this->qr ? "R" : "Q";
    this->opcode = get_opcode();
    this->aa = get_aa();
    this->tc = get_tc();
    this->rd = get_rd();
    this->ra = get_ra();
    this->ad = get_ad();
    this->cd = get_cd();
    this->rcode = get_rcode();
}

bool DNSFlags::get_qr() {
    return (this->flags >> 15) & 1;
}

int DNSFlags::get_opcode() {
    return (this->flags >> 11) & 0xF;
}

bool DNSFlags::get_aa() {
    return (this->flags >> 10) & 1; 
}

bool DNSFlags::get_tc() {
    return (this->flags >> 9) & 1;
}

bool DNSFlags::get_rd() {
    return (this->flags >> 8) & 1;
}

bool DNSFlags::get_ra() {
    return (this->flags >> 7) & 1;
}

bool DNSFlags::get_ad() {
    return (this->flags >> 5) & 1;
}

bool DNSFlags::get_cd() {
    return (this->flags >> 4) & 1;
}

int DNSFlags::get_rcode() {
    return this->flags & 0xF;
}