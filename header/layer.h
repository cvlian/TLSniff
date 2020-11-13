/* layer.h
 *
 * basic structure of a protocol layer
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER
#define PUMP_LAYER

#include <stdio.h>
#include <stdint.h>

#define PROTO_UnknownProtocol            0x00ULL
#define PROTO_Ethernet2                  0x01ULL
#define PROTO_IPv4                       0x02ULL
#define PROTO_TCP                        0x04ULL
#define PROTO_VLAN                       0x08ULL
#define PROTO_PPPoESession               0x10ULL
#define PROTO_MPLS                       0x20ULL
#define PROTO_GREv0                      0x40ULL
#define PROTO_GREv1                      0x80ULL
#define PROTO_GRE                      0x0100ULL
#define PROTO_PPP_PPTP                 0x0200ULL
#define PROTO_SLL                      0x0400ULL
#define PROTO_Payload                  0x0800ULL
#define PROTO_VXLAN                    0x1000ULL
#define PROTO_PacketTrailer            0x2000ULL
#define PROTO_Ethernet802_3            0x4000ULL

#define OSI_PhysicalLayer                   1
#define OSI_DataLinkLayer                   2
#define OSI_NetworkLayer                    3
#define OSI_TransportLayer                  4
#define OSI_SesionLayer                     5
#define OSI_PresentationLayer               6
#define OSI_ApplicationLayer                7
#define OSI_LayerUnknown                    8

namespace pump
{

    class Layer
    {

        friend class Packet;

        protected:
        
            uint8_t* l_Data;
            size_t l_DataLen;
            uint64_t l_Protocol;
            Layer* l_NextLayer;
            Layer* l_PrevLayer;

            Layer() : l_Data(NULL), l_DataLen(0), l_Protocol(PROTO_UnknownProtocol), l_NextLayer(NULL), l_PrevLayer(NULL) {}

            Layer(uint8_t* data, size_t dataLen, Layer* prevLayer) :
                l_Data(data), l_DataLen(dataLen), l_Protocol(PROTO_UnknownProtocol), l_NextLayer(NULL), l_PrevLayer(prevLayer) {}

            void setNextLayer(Layer* nextLayer) { l_NextLayer = nextLayer; }

        public:

            virtual void parseNextLayer() = 0;

            Layer* getNextLayer() const { return l_NextLayer; }

            Layer* getPrevLayer() const { return l_PrevLayer; }

            uint64_t getProtocol() const { return l_Protocol; }

            uint8_t* getData() const { return l_Data; }

            size_t getDataLen() const { return l_DataLen; }

            uint8_t* getLayerPayload() const { return l_Data + getHeaderLen(); }

            size_t getLayerPayloadSize() const { return l_DataLen - getHeaderLen(); }

            virtual uint8_t getOsiModelLayer() const = 0;

            virtual size_t getHeaderLen() const = 0;

    };
}

#endif