/***
 * ISA PROJECT
 * @file dns_sections.h
 * @author Tímea Adamčíková (xadamc09)
 */

#ifndef XADAMC09_ISA_DNS_SECTION
#define XADAMC09_ISA_DNS_SECTION

#include <string>
#include <vector>
#include <variant>
#include <memory>
#include <iostream>

struct DNSQuestion {
    std::string qname;
    std::string qtype;
    std::string qclass;
};

struct DNSRecord {
    std::string name;
    std::string type;
    std::string aclass;
    uint32_t ttl;
    std::string rdata;

    void print() const {
        std::cout << name << " " << ttl << " " << aclass << " " << type << " " << rdata << std::endl;
    }
    std::string get_name_rdata() const {
        std::string output_name = name;
        output_name.pop_back();
        return output_name + " " + rdata;
    }
};

struct dnsMX {
    std::string name;
    std::string type;
    std::string aclass;
    uint32_t ttl;
    uint16_t preference;
    std::string rdata;

    void print() const {
        std::cout << name << " " << ttl << " " << aclass << " " << type << " " << preference << " " << rdata << std::endl; // TODO CHECK
    }
};

struct dnsSOA {
    std::string name;
    std::string type;
    std::string aclass;
    uint32_t ttl;
    std::string mname;
    std::string rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum_ttl;

    void print() const {
        std::cout << name << " " << ttl << " " << aclass << " " << type << " " << mname << " " << rname << " " << serial << " " << refresh << " " 
        << retry << " " << expire << " " << minimum_ttl << std::endl; // TODO CHECK
    }
};

struct dnsSRV {
    std::string name;
    std::string type;
    std::string aclass;
    uint32_t ttl;
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    std::string target;

    void print() const {
        std::cout << name << " " << ttl << " " << aclass << " " << type << " " << priority << " " << weight << " " << port << " " << target << std::endl; // TODO CHECK
    }
};

struct PrintVisitor {
    template <typename T>
    void operator()(const T& record) const {
        record.print();
    }
};

namespace dns_sections {
    class DNSSections {
        private:
            uint8_t* current_pointer;
            void process_questions();
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA, dnsSRV>> process_other_sections(int* record_num);
            uint8_t* dns_packet_begin;
            std::string tokens_to_string(uint8_t** current_pointer);
            std::string get_type(uint16_t type);
            std::string get_class(uint16_t aclass);
            bool t_mode, d_mode;
            std::string translations_file, domains_file;
            void add_translation(DNSRecord record);

        public:
            DNSSections(int questions, int answers, int authority, int additional, uint8_t* pointer, uint8_t* dns_packet_begin,
                        bool t_mode, std::string translations_file, bool d_mode, std::string domains_file);
            int question_num, answer_num, authority_num, additional_num;
            std::vector<DNSQuestion> questions;
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA, dnsSRV>> answers;
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA, dnsSRV>> authorities;
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA, dnsSRV>> additionals;
    };
}

#endif