/* layer-gre.h
 *
 * routines for the Generic Routing Encapsulation (GRE) packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_GRE
#define PUMP_LAYER_GRE

#include "layer.h"

#pragma pack(push, 1)
    struct gre_basic_header
    {
#if (BYTE_ORDER == LITTLE_ENDIAN)
        /** Number of additional encapsulations which are permitted. 0 is the default value */
        uint8_t recursionControl:3,
        /** Strict source routing bit (GRE v0 only) */
                strictSourceRouteBit:1,
        /** Set if sequence number exists */
                sequenceNumBit:1,
        /** Set if key exists */
                keyBit:1,
        /** Set if routing exists (GRE v0 only) */
                routingBit:1,
        /** Set if checksum exists (GRE v0 only) */
                checksumBit:1;
#else
        /** Set if checksum exists (GRE v0 only) */
        uint8_t checksumBit:1,
        /** Set if routing exists (GRE v0 only) */
                routingBit:1,
        /** Set if key exists */
                keyBit:1,
        /** Set if sequence number exists */
                sequenceNumBit:1,
        /** Strict source routing bit (GRE v0 only) */
                strictSourceRouteBit:1,
        /** Number of additional encapsulations which are permitted. 0 is the default value */
                recursionControl:3;
#endif
#if (BYTE_ORDER == LITTLE_ENDIAN)
        /** GRE version - can be 0 or 1 */
        uint8_t version:3,
        /** Reserved */
                flags:4,
        /** Set if acknowledgment number is set (GRE v1 only) */
                ackSequenceNumBit:1;
#else
        /** Set if acknowledgment number is set (GRE v1 only) */
        uint8_t ackSequenceNumBit:1,
        /** Reserved */
                flags:4,
        /** GRE version - can be 0 or 1 */
                version:3;
#endif
        /** Protocol type of the next layer */
        uint16_t protocol;
    };
#pragma pack(pop)

#pragma pack(push, 1)
    struct gre1_header : gre_basic_header
    {
        /** Size of the payload not including the GRE header */
        uint16_t payloadLength;
        /** Contains the Peer's Call ID for the session to which this packet belongs */
        uint16_t callID;
    };
#pragma pack(pop)

#pragma pack(push, 1)
    struct ppp_pptp_header
    {
        /** Broadcast address */
        uint8_t address;
        /** Control byte */
        uint8_t control;
        /** Protocol type of the next layer (see PPP_* macros at PPPoELayer.h) */
        uint16_t protocol;
    };
#pragma pack(pop)

namespace pump
{

    class GreLayer : public Layer
    {

        public:

            static uint64_t getGREVersion(uint8_t* greData, size_t greDataLen);

            void parseNextLayer();

            uint8_t getOsiModelLayer() const { return OSI_NetworkLayer; }

            size_t getHeaderLen() const;

        protected:

            GreLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) {}

    };

    class GREv0Layer : public GreLayer
    {

        public:

            GREv0Layer(uint8_t* data, size_t dataLen, Layer* prevLayer) : GreLayer(data, dataLen, prevLayer) { l_Protocol = PROTO_GREv0; }

            gre_basic_header* getGreHeader() const { return (gre_basic_header*)l_Data; }

    };

    class GREv1Layer : public GreLayer
    {

        public:

            GREv1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer) : GreLayer(data, dataLen, prevLayer) { l_Protocol = PROTO_GREv1; }

            gre1_header* getGreHeader() const { return (gre1_header*)l_Data; }

    };

    class PPP_PPTPLayer : public Layer
    {
            
        public:

            PPP_PPTPLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) { l_Protocol = PROTO_PPP_PPTP; }

            void parseNextLayer();

            uint8_t getOsiModelLayer() const { return OSI_SesionLayer; }

            ppp_pptp_header* getPPP_PPTPHeader() const { return (ppp_pptp_header*)l_Data; }

            size_t getHeaderLen() const { return sizeof(ppp_pptp_header); }

    };
}

#endif