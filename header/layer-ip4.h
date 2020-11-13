/* layer-ip4.h
 *
 * routines for the IPv4 packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_IP4
#define PUMP_LAYER_IP4

#include <string.h>
#include <arpa/inet.h>

#include <string>

#include "layer.h"

#pragma pack(push, 1)
    struct iphdr {
#if (BYTE_ORDER == LITTLE_ENDIAN)
        uint8_t internetHeaderLength:4,
        ipVersion:4;
#else
        uint8_t ipVersion:4,
        internetHeaderLength:4;
#endif
        uint8_t typeOfService;
        uint16_t totalLength;
        uint16_t ipId;
        uint16_t fragmentOffset;
        uint8_t timeToLive;
        uint8_t protocol;
        uint16_t headerChecksum;
        uint32_t ipSrc;
        uint32_t ipDst;
    };
#pragma pack(pop)

#define IPV4PROTO_IP         0  /** IPv6 Hop-by-Hop options */
#define IPV4PROTO_IPIP       4  /** Transmission Control Protocol	*/
#define IPV4PROTO_TCP        6  /** Exterior Gateway Protocol */
#define IPV4PROTO_GRE       47  /** encapsulating security payload */

#define IP_DONT_FRAGMENT  0x40
#define IP_MORE_FRAGMENTS 0x20

namespace pump
{

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

            IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer);

            bool isFragment() const;

            uint8_t getFragmentFlags() const;

            uint16_t getFragmentOffset() const;

            IPv4Address getSrcIpAddress() const { return getIPv4Header()->ipSrc; }

            IPv4Address getDstIpAddress() const { return getIPv4Header()->ipDst; }

            void parseNextLayer();

            uint8_t getOsiModelLayer() const { return OSI_NetworkLayer; }

            iphdr* getIPv4Header() const { return (iphdr*)l_Data; }

            size_t getHeaderLen() const { return (size_t)((uint16_t)(getIPv4Header()->internetHeaderLength) * 4); }

            static inline bool isDataValid(const uint8_t* data, size_t dataLen);

    };

    bool IPv4Layer::isDataValid(const uint8_t* data, size_t dataLen)
    {
        const iphdr* hdr = reinterpret_cast<const iphdr*>(data);
        return dataLen >= sizeof(iphdr) && hdr->ipVersion == 4 && hdr->internetHeaderLength >= 5;
    }

    in_addr* sockaddr2in_addr(struct sockaddr *sa);

    void sockaddr2string(struct sockaddr *sa, char* resultString);

}

#endif