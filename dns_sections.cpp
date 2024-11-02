/***
 * ISA PROJECT
 * @file dns_sections.cpp
 * @author Tímea Adamčíková (xadamc09)
 */

#include <iostream>
#include <arpa/inet.h>
#include <fstream>
#include "dns_sections.h"
#include "my_exception.h"

using namespace dns_sections;

DNSSections::DNSSections(int questions, int answers, int authority, int additional, uint8_t* pointer, uint8_t* dns_packet_begin,
                        bool t_mode, std::string translations_file, bool d_mode, std::string domains_file) {
    this->question_num = questions;
    this->answer_num = answers;
    this->authority_num = authority;
    this->additional_num = additional;
    this->current_pointer = pointer;
    this->dns_packet_begin = dns_packet_begin;
    this->t_mode = t_mode;
    this->translations_file = translations_file;
    this->d_mode = d_mode;
    this->domains_file = domains_file;

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

std::string DNSSections::get_class(uint16_t aclass) {
    switch (aclass) {
        case 1:
            return "IN";
        case 2:
            return "CS";
        case 3:
            return "CH";
        case 4:
            return "HS";
        default:
            return "Unknown";
    }
}

void DNSSections::add_translation(DNSRecord record) {
    std::ifstream file(this->translations_file);
    // structured translation
    std::string new_translation = record.get_name_rdata();
    bool first_translation = true;

    if (file.is_open()) {
        std::string translation;
        // read if translation is already written
        while (getline(file, translation)) {
            first_translation = false;
            if (new_translation == translation) {
                return;
            }
        }
        file.close();
    } else {
        std::cerr << "cannot open file" << std::endl;
    }

    std::ofstream outfile;
    // add new translation
    outfile.open(this->translations_file, std::ios_base::app);
    // do not write new line for the first translation
    if (first_translation) {
        outfile << new_translation;    
    } else {
        outfile << std::endl << new_translation;
    }
    outfile.close();
}
// TODO check if file does exist
void DNSSections::add_domain_name(std::string domain_name) {
    std::ifstream file(this->domains_file);
    bool first_domain_name = true;
    domain_name.pop_back(); // remove trailing dot

    if (file.is_open()) {
        std::string domain_in_file;
        // read if domain name is already written
        while (getline(file, domain_in_file)) {
            first_domain_name = false;
            if (domain_name == domain_in_file) {
                return;
            }
        }
        file.close();
    } else {
        std::cerr << "Cannot open file" << std::endl;
    }

    std::ofstream outfile;
    // add new domain name
    outfile.open(this->domains_file, std::ios_base::app);
    // do not write new line for the first domain name
    if (first_domain_name) {
        outfile << domain_name;    
    } else {
        outfile << std::endl << domain_name;
    }
    outfile.close();
}

std::string DNSSections::tokens_to_string(uint8_t** current_ptr) { // TODO should be trailing dot removed??????
    std::string name = "";

    while (1) {
        uint8_t tokens_count = (*current_ptr)[0];

        if (tokens_count  == 0xC0) {
            uint8_t name_offset = *(*current_ptr + 1); 
            *current_ptr += 2;
            
            uint8_t* name_begin = this->dns_packet_begin + name_offset;
            name += tokens_to_string(&name_begin); // TODO better check me
            break;
        }

        *current_ptr = *current_ptr + 1;
        if (tokens_count == 0) {
            break;
        }
        for(uint8_t processed_tokens = 0; processed_tokens < tokens_count; processed_tokens++) {
            name += (*current_ptr)[0];
            *current_ptr = *current_ptr + 1;
        }
        name += ".";
    }
    // name.pop_back(); // remove trailing dot
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
            // qtype is not supported
            this->current_pointer += 2;
            continue;
        }

        uint16_t *qclass = (uint16_t *)this->current_pointer;
        this->current_pointer += 2;

        DNSQuestion question = {.qname=qname, .qtype=qtype, .qclass=this->get_class(ntohs(*qclass))};
        this->questions.push_back(question);
        if (this->d_mode) {
            this->add_domain_name(qname);
        }
    }

    this->question_num = this->questions.size();
}

std::vector<std::variant<DNSRecord, dnsMX, dnsSOA, dnsSRV>> DNSSections::process_other_sections(int* record_num) {
    // process records
    std::vector<std::variant<DNSRecord, dnsMX, dnsSOA, dnsSRV>> records;

    for(int i = 0; i < *record_num; i++) {
        std::string name = "";
        // TODO CHECK ME
        if ((this->current_pointer[0] & 0xC0) == 0xC0) { // check if it is a pointer (C0 or C1)
            uint16_t name_offset = ((this->current_pointer[0] & 0x3F) << 8) | this->current_pointer[1];
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
            // skipping record
            this->current_pointer += 6; 
            uint16_t* data_length = (uint16_t *)this->current_pointer;
            this->current_pointer += 2;
            // move past data from record
            this->current_pointer += ntohs(*data_length);
            continue;
        }

        uint16_t *aclass = (uint16_t *)this->current_pointer;
        this->current_pointer += 2; 

        uint32_t *ttl = (uint32_t *)this->current_pointer;
        this->current_pointer += 4;

        uint16_t *data_lenght = (uint16_t *)this->current_pointer;
        this->current_pointer += 2;

        std::string rdata;

        if (type == "MX") {
            uint16_t *preference = (uint16_t *)this->current_pointer;
            this->current_pointer += 2;
            std::string rdata = tokens_to_string(&this->current_pointer);
            dnsMX mx_record = {.name=name, .type=type, .aclass=this->get_class(ntohs(*aclass)), .ttl=ntohl(*ttl), .preference=ntohs(*preference), .rdata=rdata};
            records.push_back(mx_record);

            if (this->d_mode) {
                this->add_domain_name(name);
                this->add_domain_name(rdata);
            }
            continue;
        } else if (type == "A") {
            char ip[INET_ADDRSTRLEN];
            const char* result = inet_ntop(AF_INET, (void*)this->current_pointer, ip, sizeof(ip));
            rdata = std::string(result == nullptr ? "" : result);
            this->current_pointer += 4;
        } else if (type == "AAAA") {
            char ip[INET6_ADDRSTRLEN];
            const char* result = inet_ntop(AF_INET6, (void*)this->current_pointer, ip, sizeof(ip));
            rdata = std::string(result == nullptr ? "" : result);
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

            dnsSOA soa_record = {.name=name, .type=type, .aclass=this->get_class(ntohs(*aclass)), .ttl=ntohl(*ttl), .mname=mname, .rname=rname,
                                .serial=ntohl(*serial_number), .refresh=ntohl(*refresh_interval), .retry=ntohl(*retry_interval), 
                                .expire=ntohl(*expire_limit), .minimum_ttl=ntohl(*minimum_ttl)};
            records.push_back(soa_record);

            if (this->d_mode) {
               this->add_domain_name(name);
               this->add_domain_name(mname);
            }

            continue;
        } else if (type == "SRV") {
            uint16_t *priority = (uint16_t *)this->current_pointer;
            this->current_pointer += 2;
            uint16_t *weigth = (uint16_t *)this->current_pointer;
            this->current_pointer += 2;
            uint16_t *port = (uint16_t *)this->current_pointer;
            this->current_pointer += 2;
            std::string target = tokens_to_string(&this->current_pointer);

            dnsSRV record = {.name=name, .type=type, .aclass=this->get_class(ntohs(*aclass)), .ttl=ntohl(*ttl), .priority=ntohs(*priority), .weight=ntohs(*weigth),
                            .port=ntohs(*port), .target=target};
            
            records.push_back(record);

            if (this->d_mode) {
               this->add_domain_name(target);
            }

            continue;
        } else {
            rdata = tokens_to_string(&this->current_pointer);
        }

        DNSRecord record = {.name=name, .type=type, .aclass=this->get_class(ntohs(*aclass)), .ttl=ntohl(*ttl), .rdata=rdata};

        if (this->t_mode && (type == "A" || type == "AAAA")) {
            this->add_translation(record);
        }

        if (this->d_mode && (type != "A" && type != "AAAA")) {
            this->add_domain_name(name);
            this->add_domain_name(rdata);
        } else if (this->d_mode) {
            this->add_domain_name(name);
        }

        records.push_back(record);
    }

    // get number of supported records
    *record_num = records.size();
    return records;
}