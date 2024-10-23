#include <iostream>
#include <arpa/inet.h>
#include "dns_sections.h"
#include "my_exception.h"

using namespace dns_sections;

DNSSections::DNSSections(int questions, int answers, int authority, int additional, uint8_t* pointer, uint8_t* dns_packet_begin) {
    this->question_num = questions;
    this->answer_num = answers;
    this->authority_num = authority;
    this->additional_num = additional;
    this->current_pointer = pointer;
    this->dns_packet_begin = dns_packet_begin;

    this->process_questions();

    this->answers = this->process_other_sections(&this->answer_num);
    this->authorities = this->process_other_sections(&this->authority_num);
    this->additionals = this->process_other_sections(&this->additional_num);
}

std::string DNSSections::get_type(uint16_t type) {
    switch (type) {
        case 1:
            return "A";
        case 2:
            return "NS";
        case 5:
            return "CNAME";
        case 6:
            return "SOA";
        case 15:
            return "MX";
        case 28:
            return "AAAA";
        case 33:
            return "SRV";
        default:
            throw IgnoreRecord();
            return "";
    }
}

std::string DNSSections::tokens_to_string(uint8_t** current_ptr) { // TODO should be trailing dot removed??????
    std::string name = "";
    bool should_break = false;
    while (1) {
        uint8_t tokens_count = (*current_ptr)[0];
        *current_ptr = *current_ptr + 1;
        if (tokens_count == 0) {
            break;
        }
        for(uint8_t processed_tokens = 0; processed_tokens < tokens_count; processed_tokens++) {
            if ((*current_ptr)[0] == 0xC0) {
                uint8_t name_offset = *(*current_ptr + 1); 
                *current_ptr += 2;
                
                uint8_t* name_begin = this->dns_packet_begin + name_offset;
                name += tokens_to_string(&name_begin); // TODO better check me
                should_break = true;
                break;
            } else {
                name += (*current_ptr)[0];
                *current_ptr = *current_ptr + 1;
            }
        }
        name += ".";

        if (should_break) {
            break;
        }
    }
    name.pop_back(); // remove trailing dot
    return name;
}

void DNSSections::process_questions() {
    // process questions
    for(int i = 0; i < this->question_num; i++) {
        std::string qname = tokens_to_string(&(this->current_pointer));
        uint16_t *qtype_value = (uint16_t *)this->current_pointer;
        this->current_pointer += 2;
        std::string qtype;

        try {
            qtype = this->get_type(ntohs(*qtype_value));
        } catch (const IgnoreRecord& e) {
            this->current_pointer += 2;
            continue;
        }

        uint16_t *qclass = (uint16_t *)this->current_pointer;
        this->current_pointer += 2;

        DNSQuestion question = {.qname=qname, .qtype=qtype, .qclass=ntohs(*qclass)};
        this->questions.push_back(question);
        std::cout << "QNAME=" << question.qname << std::endl;
        std::cout << "QTYPE=" << question.qtype << std::endl;
        std::cout << "QCLASS=" << question.qclass << std::endl;
    }
}

std::vector<std::variant<DNSRecord, dnsMX, dnsSOA>> DNSSections::process_other_sections(int* record_num) {
    // process records
    std::vector<std::variant<DNSRecord, dnsMX, dnsSOA>> records;

    for(int i = 0; i < *record_num; i++) {
        std::cout << "Processing A" << i << std::endl;
        std::string name = "";
        if (this->current_pointer[0] == 0xC0) {
            uint8_t name_offset = *(this->current_pointer + 1); 
            this->current_pointer += 2;
            
            uint8_t* name_begin = this->dns_packet_begin + name_offset;
            name = tokens_to_string(&name_begin); // TODO better check me
        } else {
            name = tokens_to_string(&this->current_pointer);
        }

        uint16_t *type_value = (uint16_t *)this->current_pointer;
        this->current_pointer += 2;
        std::string type;

        try {
            type = this->get_type(ntohs(*type_value));
        } catch (const IgnoreRecord& e) {
            this->current_pointer += 6; 
            uint16_t* data_length = (uint16_t *)this->current_pointer;
            this->current_pointer += 2;
            this->current_pointer += ntohs(*data_length);
            std::cout << "hereeeeeeeeeeeeee????" << ntohs(*type_value) << std::endl << std::endl;
            continue;
        }

        uint16_t *aclass = (uint16_t *)this->current_pointer;
        this->current_pointer += 2; 

        uint32_t *ttl = (uint32_t *)this->current_pointer;
        this->current_pointer += 4;

        uint16_t *data_lenght = (uint16_t *)this->current_pointer;
        this->current_pointer += 2;

        std::string rdata;
        std::cout << "hereeeeeeeeeeeeee horeeee: " << type << std::endl << std::endl;

        if (type == "MX") {
            uint16_t *preference = (uint16_t *)this->current_pointer;
            this->current_pointer += 2;
            std::string rdata = tokens_to_string(&this->current_pointer);
            dnsMX mx_record = {.name=name, .type=type, .aclass=ntohs(*aclass), .ttl=ntohl(*ttl), .preference=ntohs(*preference), .rdata=rdata};
            records.push_back(mx_record);

            std::cout << "NAME=" << mx_record.name << std::endl;
            std::cout << "TYPE=" << mx_record.type << std::endl;
            std::cout << "CLASS=" << mx_record.aclass << std::endl;
            std::cout << "TTL=" << mx_record.ttl << std::endl;
            std::cout << "PREFERENCE=" << mx_record.preference << std::endl;
            std::cout << "RDATA=" << mx_record.rdata << std::endl << std::endl;
            continue;
        } else if (type == "A") {
            std::cout << "hereeeeeeeeeeeeee: " << type << std::endl << std::endl;

            char ip[INET_ADDRSTRLEN];
            const char* result = inet_ntop(AF_INET, (void*)this->current_pointer, ip, sizeof(ip));
            rdata = std::string(result == nullptr ? "" : result);
            std::cout << "ipv4=====================" << rdata << std::endl << std::endl;

            this->current_pointer += 4;
        } else if (type == "AAAA") {
            char ip[INET6_ADDRSTRLEN];
            const char* result = inet_ntop(AF_INET6, (void*)this->current_pointer, ip, sizeof(ip));
            rdata = std::string(result == nullptr? "" : result);
            this->current_pointer += 16;
        } else if (type == "SOA") {
            std::string mname = tokens_to_string(&this->current_pointer);
            std::string rname = tokens_to_string(&this->current_pointer);
            uint32_t *serial_number = (uint32_t *)this->current_pointer;
            this->current_pointer += 4;
            uint32_t *refresh_interval = (uint32_t *)this->current_pointer;
            this->current_pointer += 4;
            uint32_t *retry_interval = (uint32_t *)this->current_pointer;
            this->current_pointer += 4;
            uint32_t *expire_limit = (uint32_t *)this->current_pointer;
            this->current_pointer += 4;
            uint32_t *minimum_ttl = (uint32_t *)this->current_pointer;
            this->current_pointer += 4;

            dnsSOA soa_record = {.name=name, .type=type, .aclass=ntohs(*aclass), .ttl=ntohl(*ttl), .mname=mname, .rname=rname,
                                .serial=ntohl(*serial_number), .refresh=ntohl(*refresh_interval), .retry=ntohl(*retry_interval), 
                                .expire=ntohl(*expire_limit), .minimum_ttl=ntohl(*minimum_ttl)};
            records.push_back(soa_record);

            std::cout << "NAME=" << soa_record.name << std::endl;
            std::cout << "TYPE=" << soa_record.type << std::endl;
            std::cout << "CLASS=" << soa_record.aclass << std::endl;
            std::cout << "TTL=" << soa_record.ttl << std::endl;
            std::cout << "MNAME=" << soa_record.mname << std::endl;
            std::cout << "RNAME=" << soa_record.rname << std::endl;
            std::cout << "SERIAL=" << soa_record.serial << std::endl;
            std::cout << "REFRESH=" << soa_record.refresh << std::endl;
            std::cout << "RETRY=" << soa_record.retry << std::endl;
            std::cout << "EXPIRE=" << soa_record.expire << std::endl;
            std::cout << "MINIMUM TTL=" << soa_record.minimum_ttl << std::endl << std::endl;
            continue;
        } else {
            rdata = tokens_to_string(&this->current_pointer);
        }

        DNSRecord record = {.name=name, .type=type, .aclass=ntohs(*aclass), .ttl=ntohl(*ttl), .rdata=rdata};
        records.push_back(record);

        std::cout << "NAME=" << record.name << std::endl;
        std::cout << "TYPE=" << record.type << std::endl;
        std::cout << "CLASS=" << record.aclass << std::endl;
        std::cout << "TTL=" << record.ttl << std::endl;
        std::cout << "RDATA=" << record.rdata << std::endl << std::endl;
    }

    *record_num = records.size();
    return records;
}