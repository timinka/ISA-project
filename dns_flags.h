/***
 * ISA PROJECT
 * @file dns_flags.h
 * @author Tímea Adamčíková (xadamc09)
 */

#ifndef XADAMC09_ISA_DNS_FLAGS
#define XADAMC09_ISA_DNS_FLAGS

#include <pcap.h>
#include <string>

namespace dns_flags {
    class DNSFlags {
        private:
            bool get_qr();
            int get_opcode();
            bool get_aa();
            bool get_tc();
            bool get_rd();
            bool get_ra();
            bool get_ad();
            bool get_cd();
            int get_rcode(); 
            uint16_t flags;

        public:
            /**
             * @brief Constructor for DNSFlags
             * 
             * Extract indiviual flags 
             */
            DNSFlags(uint16_t flags);

            /**
             * @brief DNS packet flags. 
             * 
             * qr - Query/Response, 
             * aa - Authoritative Answer, 
             * tc- Truncation, 
             * rd - Recursion Desired, 
             * ra - Recursion Available, 
             * ad - Authentic Data, 
             * cd - Checking Disabled
             */
            bool qr, aa, tc, rd, ra, ad, cd;

            /**
             * @brief DNS operation code (OPCODE) and response code (RCODE, indicating error/status)
             */
            int opcode, rcode;

            /**
             * @brief Query or response in string format
             */
            std::string query_response;
    };
}

#endif