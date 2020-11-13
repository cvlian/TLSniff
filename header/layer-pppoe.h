/* layer-pppoe.h
 *
 * routines for the PPP Over Ethernet (PPPoE) packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_PPPOE
#define PUMP_LAYER_PPPOE

#include "layer.h"

#pragma pack(push, 1)
    struct pppoe_header {
#if (BYTE_ORDER == LITTLE_ENDIAN)
        /** PPPoE version */
        uint8_t version:4,
        /** PPPoE type */
        type:4;
        /** PPPoE code */
        uint8_t code;
#else
        /** PPPoE version */
        uint16_t version:4,
        /** PPPoE type */
        type:4,
        /** PPPoE code */
        code:8;
#endif
        /** PPPoE session ID (relevant for PPPoE session packets only) */
        uint16_t sessionId;
        /** Length (in bytes) of payload, not including the PPPoE header */
        uint16_t payloadLength;
    };
#pragma pack(pop)

/** Padding Protocol */
#define PPPoE_IP       0x21

namespace pump
{
    
    class PPPoELayer : public Layer
    {
        public:

            pppoe_header* getPPPoEHeader() const { return (pppoe_header*)l_Data; }

            uint8_t getOsiModelLayer() const { return OSI_DataLinkLayer; }

        protected:

            PPPoELayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) {}

    };

    class PPPoESessionLayer : public PPPoELayer
    {

        public:

            PPPoESessionLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : PPPoELayer(data, dataLen, prevLayer) { l_Protocol = PROTO_PPPoESession; }

            uint16_t getPPPNextProtocol() const;

            virtual void parseNextLayer();

            virtual size_t getHeaderLen() const { return sizeof(pppoe_header) + sizeof(uint16_t); }

            static inline bool isDataValid(const uint8_t* data, size_t dataLen);

    };

    bool PPPoESessionLayer::isDataValid(const uint8_t* data, size_t dataLen)
    {
        return dataLen >= sizeof(pppoe_header) + sizeof(uint16_t);
    }

}

#endif