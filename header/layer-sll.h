/* layer-sll.h
 *
 * routines for the Linux "cooked mode" packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_SLL
#define PUMP_LAYER_SLL

#include "layer.h"

#pragma pack(push, 1)
    struct sll_header
    {
        uint16_t packet_type;
        uint16_t ARPHRD_type;
        uint16_t link_layer_addr_len;
        uint8_t link_layer_addr[8];
        uint16_t protocol_type;
    };
#pragma pack(pop)

namespace pump
{

    class SllLayer : public Layer
    {

        public:

            SllLayer(uint8_t* data, size_t dataLen) : Layer(data, dataLen, NULL) { l_Protocol = PROTO_SLL; }

            void parseNextLayer();

            uint8_t getOsiModelLayer() const { return OSI_DataLinkLayer; }

            sll_header* getSllHeader() const { return (sll_header*)l_Data; }

            size_t getHeaderLen() const { return sizeof(sll_header); }
            
    };

}

#endif