/* layer-payload.h
 *
 * routines for the data packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_PAYLOAD
#define PUMP_LAYER_PAYLOAD

#include "layer.h"

namespace pump
{

    class PayloadLayer : public Layer
    {

        public:

            PayloadLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) { l_Protocol = PROTO_Payload; }

            PayloadLayer(const uint8_t* data, size_t dataLen, bool dummy);

            void parseNextLayer() {}

            uint8_t getOsiModelLayer() const { return OSI_ApplicationLayer; }

            size_t getHeaderLen() const { return l_DataLen; }

    };

    class PacketTrailerLayer : public Layer
    {

        public:

            PacketTrailerLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) { l_Protocol = PROTO_PacketTrailer; }

            void parseNextLayer() {}

            uint8_t getOsiModelLayer() const { return OSI_DataLinkLayer; }

            size_t getHeaderLen() const { return l_DataLen; }

    };
    
}

#endif