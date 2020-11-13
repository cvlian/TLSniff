/* layer-eth.h
 *
 * routines for the ethernet packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_ETH
#define PUMP_LAYER_ETH

#include <string.h>

#include "layer.h"

#pragma pack(push, 1)
    struct ether2_header {
        uint8_t dstMac[6];        /** Destination MAC */
        uint8_t srcMac[6];        /** Source MAC */
        uint16_t etherType;       /** EtherType */
    };
#pragma pack(pop)

#pragma pack(push, 1)
    struct ether802_3_header {
        uint8_t dstMac[6];       /** Destination MAC */
        uint8_t srcMac[6];       /** Source MAC */
        uint16_t length;         /** Length */
    };
#pragma pack(pop)

#define	ETHERTYPE_IP             0x0800  /** IP */
#define	ETHERTYPE_ARP            0x0806  /** Address resolution */
#define	ETHERTYPE_VLAN           0x8100  /** IEEE 802.1Q VLAN tagging */
#define	ETHERTYPE_IPV6           0x86dd  /** IP protocol version 6 */
#define ETHERTYPE_PPPOES         0x8864  /** PPPoE session */
#define ETHERTYPE_MPLS           0x8847  /** MPLS */
#define ETHERTYPE_PPP            0x880B  /** Point-to-point protocol (PPP) */

namespace pump
{
    
    class EthLayer : public Layer
    {

        public:

            uint8_t getOsiModelLayer() const { return OSI_DataLinkLayer; }

        protected:

            EthLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) {}

    };

    class Eth2Layer : public EthLayer
    {

        public:

            Eth2Layer(uint8_t* data, size_t dataLen): EthLayer(data, dataLen, NULL) { l_Protocol = PROTO_Ethernet2; }

            Eth2Layer(uint8_t* data, size_t dataLen, Layer* prevLayer) : EthLayer(data, dataLen, prevLayer) { l_Protocol = PROTO_Ethernet2; }

            void parseNextLayer();

            ether2_header* getEthHeader() const { return (ether2_header*)l_Data; }

            size_t getHeaderLen() const { return sizeof(ether2_header); }

    };

    class Eth802_3Layer : public EthLayer
    {

        public:

            Eth802_3Layer(uint8_t* data, size_t dataLen) : EthLayer(data, dataLen, NULL) { l_Protocol = PROTO_Ethernet802_3; }

            void parseNextLayer();

            size_t getHeaderLen() const { return sizeof(ether802_3_header); }

    };

}

#endif