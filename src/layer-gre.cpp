/* layer-gre.cpp
 * 
 * routines for the Generic Routing Encapsulation (GRE) packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include <arpa/inet.h>

#include "layer-eth.h"
#include "layer-gre.h"
#include "layer-ip4.h"
#include "layer-mpls.h"
#include "layer-vlan.h"
#include "layer-pppoe.h"
#include "layer-payload.h"

namespace pump
{
    
    uint64_t GreLayer::getGREVersion(uint8_t* greData, size_t greDataLen)
    {
        if (greDataLen < sizeof(gre_basic_header))
            return PROTO_UnknownProtocol;

        uint8_t version = *(greData+1);
        version &= 0x07;
        if (version == 0)
            return PROTO_GREv0;
        else if (version == 1)
            return PROTO_GREv1;
        else
            return PROTO_UnknownProtocol;
    }

    size_t GreLayer::getHeaderLen() const
    {
        size_t result = sizeof(gre_basic_header);

        gre_basic_header* header = (gre_basic_header*)l_Data;

        if (header->checksumBit == 1 || header->routingBit == 1 )
            result += 4;
        if (header->keyBit == 1)
            result += 4;
        if (header->sequenceNumBit == 1)
            result += 4;
        if (header->ackSequenceNumBit == 1)
            result += 4;

        return result;
    }

    void GreLayer::parseNextLayer()
    {
        size_t headerLen = getHeaderLen();
        if (l_DataLen <= headerLen)
            return;

        gre_basic_header* header = (gre_basic_header*)l_Data;
        uint8_t* payload = l_Data + headerLen;
        size_t payloadLen = l_DataLen - headerLen;

        switch (be16toh(header->protocol))
        {
            case ETHERTYPE_IP:
                l_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
                    ? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this))
                    : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this));
                break;
            /* Does nothing for this layer (Dismiss IPV6 for this version...)
            case ETHERTYPE_IPV6:
            */
            case ETHERTYPE_VLAN:
                l_NextLayer = new VlanLayer(payload, payloadLen, this);
                break;
            case ETHERTYPE_MPLS:
                l_NextLayer = new MplsLayer(payload, payloadLen, this);
                break;
            case ETHERTYPE_PPP:
                l_NextLayer = new PPP_PPTPLayer(payload, payloadLen, this);
                break;
            default:
                l_NextLayer = new PayloadLayer(payload, payloadLen, this);
        }
    }

    void PPP_PPTPLayer::parseNextLayer()
    {
        size_t headerLen = getHeaderLen();
        if (l_DataLen <= headerLen)
            return;

        uint8_t* payload = l_Data + headerLen;
        size_t payloadLen = l_DataLen - headerLen;

        switch (be16toh(getPPP_PPTPHeader()->protocol))
        {
            case PPPoE_IP:
                l_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
                    ? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this))
                    : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this));
                break;
            /* Does nothing for this layer (Dismiss IPV6 for this version...)
            case PPPoE_IPV6:
            */
            default:
                l_NextLayer = new PayloadLayer(payload, payloadLen, this);
                break;
        }
    }

}