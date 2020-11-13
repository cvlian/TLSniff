/* layer-mpls.h
 *
 * routines for the Multiprotocol Label Switching (MPLS) packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_MPLS
#define PUMP_LAYER_MPLS

#include "layer.h"

#pragma pack(push, 1)
struct mpls_header
{
    uint16_t    hiLabel;
    uint8_t		misc;
    uint8_t		ttl;
};
#pragma pack(pop)

namespace pump
{

    class MplsLayer : public Layer
    {

        public:

            MplsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) { l_Protocol = PROTO_MPLS; }

            bool isBottomOfStack() const;

            void parseNextLayer();

            uint8_t getOsiModelLayer() const { return OSI_NetworkLayer; }

            mpls_header* getMplsHeader() const { return (mpls_header*)l_Data; }

            size_t getHeaderLen() const { return sizeof(mpls_header); }
            
    };

}

#endif