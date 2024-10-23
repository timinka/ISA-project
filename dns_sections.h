#ifndef XADAMC09_ISA_DNS_SECTION
#define XADAMC09_ISA_DNS_SECTION

#include <string>
#include <vector>
#include <variant>
#include <memory>

struct DNSQuestion {
    std::string qname;
    std::string qtype;
    uint16_t qclass;
};

struct DNSRecord {
    std::string name;
    std::string type;
    uint16_t aclass;
    uint32_t ttl;
    std::string rdata;
};

struct dnsMX {
    std::string name;
    std::string type;
    uint16_t aclass;
    uint32_t ttl;
    uint16_t preference;
    std::string rdata;
};

struct dnsSOA {
    std::string name;
    std::string type;
    uint16_t aclass;
    uint32_t ttl;
    std::string mname;
    std::string rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum_ttl;
};

namespace dns_sections {
    class DNSSections {
        private:
            int question_num, answer_num, authority_num, additional_num;
            uint8_t* current_pointer;
            void process_questions();
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA>> process_other_sections(int* record_num);
            uint8_t* dns_packet_begin;
            std::string tokens_to_string(uint8_t** current_pointer);
            std::string get_type(uint16_t type);

        public:
            DNSSections(int questions, int answers, int authority, int additional, uint8_t* pointer, uint8_t* dns_packet_begin);
            std::vector<DNSQuestion> questions;
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA>> answers;
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA>> authorities;
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA>> additionals;
    };
}

#endif