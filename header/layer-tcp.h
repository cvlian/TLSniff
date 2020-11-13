/* layer-tcp.h
 *
 * routines for the TCP packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_TCP
#define PUMP_LAYER_TCP

#include "layer.h"

#pragma pack(push,1)
    struct tcphdr {
        uint16_t portSrc;  
        uint16_t portDst;
        uint32_t sequenceNumber;
        uint32_t ackNumber;
#if (BYTE_ORDER == LITTLE_ENDIAN)
        uint16_t reserved:4,
        dataOffset:4,
        finFlag:1,
        synFlag:1,
        rstFlag:1,
        pshFlag:1,
        ackFlag:1,
        urgFlag:1,
        eceFlag:1,
        cwrFlag:1;
#elif (BYTE_ORDER == BIG_ENDIAN)
        uint16_t dataOffset:4,
        reserved:4,
        cwrFlag:1,
        eceFlag:1,
        urgFlag:1,
        ackFlag:1,
        pshFlag:1,
        rstFlag:1,
        synFlag:1,
        finFlag:1;
#else
#error	"Endian is not LE nor BE..."
#endif
        uint16_t	windowSize;
        uint16_t	headerChecksum;
        uint16_t	urgentPointer;
};
#pragma pack(pop)

namespace pump
{

    class TcpLayer : public Layer
    {

        public:

            TcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) { l_Protocol = PROTO_TCP; };

            void parseNextLayer();

            uint8_t getOsiModelLayer() const { return OSI_TransportLayer; }

            tcphdr* getTcpHeader() const { return (tcphdr*)l_Data; }

            size_t getHeaderLen() const { return getTcpHeader()->dataOffset*4 ;}

            static inline bool isDataValid(const uint8_t* data, size_t dataLen);

    };

    bool TcpLayer::isDataValid(const uint8_t* data, size_t dataLen)
    {
        const tcphdr* hdr = reinterpret_cast<const tcphdr*>(data);
        return dataLen >= sizeof(tcphdr)
        && hdr->dataOffset >= 5 /* the minimum TCP header size */
        && dataLen >= hdr->dataOffset * sizeof(uint32_t);
    }
    
}

#endif