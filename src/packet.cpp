/* packet.cpp
 * 
 * basic structure of a packet
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include <endian.h>

#include <vector>

#include "layer-eth.h"
#include "layer-ip4.h" 
#include "layer-sll.h"    
#include "layer-payload.h"
#include "packet.h"

namespace pump
{

    void Packet::Init()
    {
        pk_RawDataLen = 0;
        pk_DeleteRawDataAtDestructor = true;
        pk_LinkLayerType = LINKTYPE_ETHERNET;
        pk_FirstLayer = NULL;
        pk_LastLayer = NULL;
        pk_RawData = 0;
    }

    Packet::Packet()
    {
        Init();
    }

    Packet::Packet(const uint8_t* data, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor, uint16_t layerType)
    {
        Init();
        pk_DeleteRawDataAtDestructor = deleteRawDataAtDestructor;
        setRawData(data, rawDataLen, timestamp, layerType);
    }

    Packet::~Packet()
    {
        destructPacketData();
    }

    void Packet::destructPacketData()
    {
        if (pk_RawData != 0 && pk_DeleteRawDataAtDestructor)
        {
            delete[] pk_RawData;
        }
    }

    void Packet::setRawPacket()
    {
        pk_FirstLayer = NULL;
        pk_LastLayer = NULL;
        pk_ProtocolTypes = PROTO_UnknownProtocol;
        if (pk_RawData == 0)
            return;

        pk_FirstLayer = createFirstLayer(pk_LinkLayerType);

        pk_LastLayer = pk_FirstLayer;
        Layer* curLayer = pk_FirstLayer;

        while (curLayer != NULL)
        {
            pk_ProtocolTypes |= curLayer->getProtocol();
            curLayer->parseNextLayer();
            curLayer = curLayer->getNextLayer();
            if (curLayer != NULL)
                pk_LastLayer = curLayer;
        }
    
        if (pk_LastLayer != NULL)
        {
            int trailerLen = (int)((pk_RawData + pk_RawDataLen) - (pk_LastLayer->getData() + pk_LastLayer->getDataLen()));

            if (trailerLen > 0)
            {
                PacketTrailerLayer* trailerLayer = new PacketTrailerLayer(
                        (uint8_t*)(pk_LastLayer->getData() + pk_LastLayer->getDataLen()),
                        trailerLen,
                        pk_LastLayer);

                pk_LastLayer->setNextLayer(trailerLayer);
                pk_LastLayer = trailerLayer;
                pk_ProtocolTypes |= trailerLayer->getProtocol();
            }
        }
    }

    bool Packet::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, uint16_t layerType)
    {
        destructPacketData();

        pk_RawData = (uint8_t*)pRawData;
        pk_RawDataLen = rawDataLen;
        pk_TimeStamp = timestamp;
        pk_LinkLayerType = layerType;
        pk_FirstLayer = NULL;
        setRawPacket();

        return true;
    }
    
    Layer* Packet::createFirstLayer(uint16_t linkType)
    {
        if (pk_RawDataLen == 0)
            return NULL;

        if (linkType == LINKTYPE_ETHERNET)
        {
            if ((unsigned long)pk_RawDataLen >= sizeof(ether2_header))
            {
                uint16_t ethTypeOrLength = be16toh(*(uint16_t*)(pk_RawData + 12));
                if (ethTypeOrLength <= (uint16_t)0x5dc && ethTypeOrLength != 0)
                {
                    return new Eth802_3Layer(pk_RawData, pk_RawDataLen);
                }
                else
                {
                    return new Eth2Layer(pk_RawData, pk_RawDataLen);
                }	
            }
            else
            {
                return new PayloadLayer(pk_RawData, pk_RawDataLen, NULL);
            }
        }
        else if (linkType == LINKTYPE_LINUX_SLL)
        {
            return new SllLayer(pk_RawData, pk_RawDataLen);
        }
        /* Does nothing for this layer (NullLoopbackLayer can't have TLS records)
        else if (linkType == LINKTYPE_NULL)
        {
        }
        */
        else if (linkType == LINKTYPE_RAW || linkType == LINKTYPE_DLT_RAW1 || linkType == LINKTYPE_DLT_RAW2)
        {
            uint8_t ipVer = pk_RawData[0] & 0xf0;
            if (ipVer == 0x40)
            {
                return IPv4Layer::isDataValid(pk_RawData, pk_RawDataLen)
                    ? static_cast<Layer*>(new IPv4Layer(pk_RawData, pk_RawDataLen, NULL))
                    : static_cast<Layer*>(new PayloadLayer(pk_RawData, pk_RawDataLen, NULL));
            }
            /* Does nothing for this layer (Dismiss IPV6 for this version...)
            else if (ipVer == 0x60)
            {
            }
            */
            else
            {
                return new PayloadLayer(pk_RawData, pk_RawDataLen, NULL);
            }
        }
        else if (linkType == LINKTYPE_IPV4)
        {
            return IPv4Layer::isDataValid(pk_RawData, pk_RawDataLen)
                ? static_cast<Layer*>(new IPv4Layer(pk_RawData, pk_RawDataLen, NULL))
                : static_cast<Layer*>(new PayloadLayer(pk_RawData, pk_RawDataLen, NULL));
        }
        /* Does nothing for this layer (Dismiss IPV6 for this version...)
        else if (linkType == LINKTYPE_IPV6)
        {
        }
        */

        return new PayloadLayer(pk_RawData, pk_RawDataLen, NULL);
    }

    void Packet::clear()
    {
        if (pk_RawData != 0)
            delete[] pk_RawData;

        pk_RawData = 0;
        pk_RawDataLen = 0;
    }

}