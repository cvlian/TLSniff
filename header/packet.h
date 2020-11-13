/* packet.h
 * 
 * basic structure of a packet
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_PACKET
#define PUMP_PACKET

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <vector>

#include "layer.h"

#define LINKTYPE_ETHERNET          1
#define LINKTYPE_DLT_RAW1         12
#define LINKTYPE_DLT_RAW2         14
#define LINKTYPE_RAW             101
#define LINKTYPE_LINUX_SLL       113
#define LINKTYPE_IPV4            228

#define MAX_PACKET_SIZE        65536

namespace pump
{

    class Packet
    {

        friend class Layer;

        protected:
            
            uint8_t* pk_RawData;
            int pk_RawDataLen;
            bool pk_DeleteRawDataAtDestructor;
            uint16_t pk_LinkLayerType;
            uint64_t pk_ProtocolTypes;
            timeval pk_TimeStamp;
            Layer* pk_FirstLayer;
            Layer* pk_LastLayer;

            void Init();

        public:

            Packet();

            Packet(const uint8_t* data, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor, uint16_t layerType = LINKTYPE_ETHERNET);

            ~Packet();

            void destructPacketData();

            void setRawPacket();

            bool setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, uint16_t layerType = LINKTYPE_ETHERNET);
            
            Layer* createFirstLayer(uint16_t linkType);

            template<class TLayer>
            TLayer* getLayerOfType() const;

            template<class TLayer>
            TLayer* getNextLayerOfType(Layer* after) const;

            const uint8_t* getRawData() const { return pk_RawData; }

            int getRawDataLen() const { return pk_RawDataLen; }

            timeval getPacketTimeStamp() const { return pk_TimeStamp; }

            uint64_t getProtocolTypes() const { return pk_ProtocolTypes; }

            bool isPacketOfType(uint64_t protocolType) const { return pk_ProtocolTypes & protocolType; }

            void clear();

    };

    template<class TLayer>
    TLayer* Packet::getLayerOfType() const
    {
        if (dynamic_cast<TLayer*>(pk_FirstLayer) != NULL)
            return (TLayer*)pk_FirstLayer;

        return getNextLayerOfType<TLayer>(pk_FirstLayer);
    }

    template<class TLayer>
    TLayer* Packet::getNextLayerOfType(Layer* after) const
    {
        if (after == NULL)
            return NULL;

        Layer* curLayer = after->getNextLayer();
        while ((curLayer != NULL) && (dynamic_cast<TLayer*>(curLayer) == NULL))
        {
            curLayer = curLayer->getNextLayer();
        }

        return (TLayer*)curLayer;
    }

}

#endif