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


/**
 * @brief Representation of DNS query question
 * 
 * - `qname` - Domain name being queried
 * - `qtype` - Type of DNS record
 * - `qclass` - Class of DNS record
 */
struct DNSQuestion {
    std::string qname;
    std::string qtype;
    std::string qclass;
};


/**
 * @brief Representation of generic DNS record
 * 
 * - `name` - Domain name associated with record
 * - `type` - Type of DNS record
 * - `aclass` - Class of DNS record
 * - `ttl` - Time to live
 * - `rdata` - record's data based on record type
 */
struct DNSRecord {
    std::string name;
    std::string type;
    std::string aclass;
    uint32_t ttl;
    std::string rdata;

    /**
     * @brief Print formated output of DNS record
     */
    void print() const {
        std::cout << name << " " << ttl << " " << aclass << " " << type << " " << rdata << std::endl;
    }

    /**
     * @brief Return formated name (removing trailing dot from domain name) and rdata 
     * 
     * @return Formated string 
     */
    std::string get_name_rdata() const {
        std::string output_name = name;
        output_name.pop_back();
        return output_name + " " + rdata;
    } 
};


/**
 * @brief Representation of DNS mail exchange (MX) record
 * 
 * - `name` - Domain name associated with record
 * - `type` - Type of DNS record
 * - `aclass` - Class of DNS record
 * - `ttl` - Time to live
 * - `prefernce` - Priority of mail server
 * - `rdata` - Mail server for domain name
 */
struct dnsMX {
    std::string name;
    std::string type;
    std::string aclass;
    uint32_t ttl;
    uint16_t preference;
    std::string rdata;

    /**
     * @brief Print formated output of MX record
     */
    void print() const {
        std::cout << name << " " << ttl << " " << aclass << " " << type << " " << preference << " " << rdata << std::endl; 
    }
};


/**
 * @brief Representation of DNS start of authority (SOA) record
 * 
 * - `name` - Domain name associated with record
 * - `type` - Type of DNS record
 * - `aclass` - Class of DNS record
 * - `ttl` - Time to live
 * - `mname` - Name of primary mail server
 * - `rname` - Administrator's email address
 * - `serial` - Serial number
 * - `refresh` - How long should secondary servers wait before asking primary servers
 * - `retry` - How long should server wait before asking for update
 * - `expire` - How long should secondary server wait for response from the primary server
 * - `minimum_ttl` - Minimum time to live
 */
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

    /**
     * @brief Print formated output of SOA record
     */
    void print() const {
        std::cout << name << " " << ttl << " " << aclass << " " << type << " " << mname << " " << rname << " " << serial << " " << refresh << " " 
        << retry << " " << expire << " " << minimum_ttl << std::endl; 
    }
};


/**
 * @brief Representation of DNS service record (SRV) record
 * 
 * - `name` - Domain name associated with record
 * - `type` - Type of DNS record
 * - `aclass` - Class of DNS record
 * - `ttl` - Time to live
 * - `priority` - Priority of server
 * - `weight` - Weight of server
 * - `port` - Port within target server
 * - `target` - Target server
 */
struct dnsSRV {
    std::string name;
    std::string type;
    std::string aclass;
    uint32_t ttl;
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    std::string target;

    /**
     * @brief Print formated output of SRV record
     */
    void print() const {
        std::cout << name << " " << ttl << " " << aclass << " " << type << " " << priority << " " << weight << " " << port << " " << target << std::endl; 
    }
};


/**
 * @brief Print formated output of specified DNS record
 */
struct PrintVisitor {
    template <typename T>
    void operator()(const T& record) const {
        record.print();
    }
};


namespace dns_sections {
    /**
     * @brief Class representing sections in a DNS packet (question, answer, authority and additional section)
     */
    class DNSSections {
        private:
            /**
             * @brief Pointer to current position in DNS packet
             */
            uint8_t* current_pointer;

            /**
             * @brief Processing DNS question section
             */
            void process_questions();

            /**
             * @brief Process records in other sections (answer, authority, additional)
             * 
             * @param record_num Pointer to number of records in section, it is changed based on supported types of DNS records
             * @return Vector of DNS records (including generic DNS record structure, MX, SOA and SRV)
             */
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA, dnsSRV>> process_other_sections(int* record_num);

            /**
             * @brief Pointer to the beginning of DNS packet
             */
            uint8_t* dns_packet_begin;

            /**
             * @brief Converts DNS packet tokens to string
             * 
             * @param current_pointer Pointer to the start of tokens
             * @return String representation
             */
            std::string tokens_to_string(uint8_t** current_pointer);

            /**
             * @brief Get record type in string
             * 
             * @param type Number of DNS record type
             * @return String representation of record type
             * @throw IgnoreRecord when the record type is not supported
             */
            std::string get_type(uint16_t type);

            /**
             * @brief Get class type in string
             * 
             * @param aclass Number of class type
             * @return String representation of class type 
             */
            std::string get_class(uint16_t aclass);

            /**
             * @brief Flag for capturing traslations
             */
            bool t_mode;

            /**
             * @brief Flag for capturing domain names
             */
            bool d_mode;

            /**
             * @brief File for storing translations
             */
            std::string translations_file; 

            /**
             * @brief File for storing domain names
             */
            std::string domains_file;

            /**
             * @brief Write unique translation to file
             * 
             * @param record DNS record to be written
             */
            void add_translation(DNSRecord record);

            /**
             * @brief Write unique domain name to file
             * 
             * @param domain_name Domain name to be added
             */
            void add_domain_name(std::string domain_name);

            /**
             * @brief Write output to file
             * 
             * @param file File to be written in
             * @param new_line Line to be added to file output
             */
            void write_to_file(std::string file, std::string new_line);

        public:
            /**
             * @brief Constructor for DNSSections
             * 
             * @param question Number of questions in DNS packet
             * @param answer Number of answers in DNS packet
             * @param authority Number of authority records in DNS packet
             * @param additional Number of additional records in DNS packet
             * @param pointer Pointer to current position in DNS packet
             * @param dns_packet_begin Pointer to start of DNS packet
             * @param t_mode Flag for translation mode
             * @param translations_file Name of file for storing translations (A and AAAA records)
             * @param d_mode Flag for domain name mode
             * @param domains_file Name of file for storing domain names
             */
            DNSSections(int questions, int answers, int authority, int additional, uint8_t* pointer, uint8_t* dns_packet_begin,
                        bool t_mode, std::string translations_file, bool d_mode, std::string domains_file);

            /**
             * @brief Number of records in separated sections
             */
            int question_num, answer_num, authority_num, additional_num;

            /**
             * @brief Vector holding DNS question records
             */
            std::vector<DNSQuestion> questions;

            /**
             * @brief Vector holding DNS answer records
             */
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA, dnsSRV>> answers;

            /**
             * @brief Vector holding DNS auhority records
             */
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA, dnsSRV>> authorities;

            /**
             * @brief Vector holding DNS additional records
             */
            std::vector<std::variant<DNSRecord, dnsMX, dnsSOA, dnsSRV>> additionals;
    };
}

#endif