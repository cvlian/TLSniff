/* layer-pppoe.cpp
 * 
 * routines for the PPP Over Ethernet (PPPoE) packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include <arpa/inet.h>

#include "layer-eth.h"
#include "layer-ip4.h"
#include "layer-mpls.h"
#include "layer-pppoe.h"
#include "layer-payload.h"

namespace pump
{

    uint16_t PPPoESessionLayer::getPPPNextProtocol() const
    {
        if (l_DataLen < getHeaderLen()) return 0;

        uint16_t pppNextProto = *(uint16_t*)(l_Data + sizeof(pppoe_header));
        return be16toh(pppNextProto);
    }

    void PPPoESessionLayer::parseNextLayer()
    {
        size_t headerLen = getHeaderLen();
        if (l_DataLen <= headerLen)
            return;

        uint8_t* payload = l_Data + headerLen;
        size_t payloadLen = l_DataLen - headerLen;

        switch (getPPPNextProtocol())
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