/* layer-ip.h
 *
 * routines for the IPv4 packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_IP
#define PUMP_LAYER_IP

#include <string.h>
#include <arpa/inet.h>

#include <string>

#include "layer.h"

#define IPV4PROTO_IP         0
#define IPV4PROTO_ICMP       1
#define IPV4PROTO_IPIP       4
#define IPV4PROTO_TCP        6
#define IPV4PROTO_UDP       17

#define IP_DONT_FRAGMENT        0x40
#define IP_MORE_FRAGMENTS       0x20

namespace pump
{

    typedef struct _ip_hdr 
    {
        uint8_t hdr_len:4,
                ver:4;
        uint8_t ecn:2,
                dscp:6;
        uint16_t total_len;
        uint16_t id;
        uint16_t fragoff;
        uint8_t ttl;
        uint8_t proto;
        uint16_t checksum;
        uint32_t ip_src;
        uint32_t ip_dst;
    } ip_hdr;

    class IPv4Address
    {

        public:

            IPv4Address(uint32_t addrAsInt) { memcpy(ad_Bytes, &addrAsInt, sizeof(ad_Bytes)); }

            IPv4Address(const std::string& addrAsString);

            inline uint32_t toInt() const;

            in_addr* toInAddr() const { return ad_pInAddr; }

            const uint8_t* toBytes() const { return ad_Bytes; }

            std::string toString() const;

            bool isValid() const { return toInt() != 0; }

        private:

            uint8_t ad_Bytes[4];
            in_addr* ad_pInAddr;
            
    };

    uint32_t IPv4Address::toInt() const
    {
        uint32_t addr;
        memcpy(&addr, ad_Bytes, sizeof(ad_Bytes));
        return addr;
    }

    class IPv4Layer : public Layer
    {
        
        public:

            IPv4Layer(uint8_t* data, size_t datalen, Layer* prev_layer);

            virtual ~IPv4Layer() {};

            bool isFragment() const;

            uint8_t getFragmentFlags() const { return getHeader()->fragoff & 0xE0; }

            uint16_t getFragmentOffset() const { return be16toh(getHeader()->fragoff & (uint16_t)0xFF1F) * 8; }

            IPv4Address getSrcIpAddress() const { return getHeader()->ip_src; }

            IPv4Address getDstIpAddress() const { return getHeader()->ip_dst; }

            void dissectData();

            ip_hdr* getHeader() const { return (ip_hdr*)l_data; }

            size_t getHeaderLen() const { return (size_t)((uint16_t)(getHeader()->hdr_len) * 4); }

            static bool isValidLayer(const uint8_t* data, size_t datalen);

    };

    in_addr* sockaddr2in_addr(struct sockaddr *sa);

    void sockaddr2string(struct sockaddr *sa, char* resultString);

}

#endif