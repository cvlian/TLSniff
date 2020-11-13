/* layer-mpls.cpp
 * 
 * routines for the Multiprotocol Label Switching (MPLS) packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include <arpa/inet.h>

#include "layer-eth.h"
#include "layer-ip4.h"
#include "layer-mpls.h"
#include "layer-payload.h"

namespace pump
{

    bool MplsLayer::isBottomOfStack() const
    {
        return (getMplsHeader()->misc & 0x01);
    }

    void MplsLayer::parseNextLayer()
    {
        size_t headerLen = getHeaderLen();
        if (l_DataLen < headerLen + 1)
            return;

        uint8_t* payload = l_Data + sizeof(mpls_header);
        size_t payloadLen = l_DataLen - sizeof(mpls_header);

        if (!isBottomOfStack())
        {
            l_NextLayer = new MplsLayer(payload, payloadLen, this);
            return;
        }

        uint8_t nextNibble = (*((uint8_t*)(l_Data + headerLen)) & 0xF0) >> 4;
        switch (nextNibble)
        {
            case 4:
                l_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
                    ? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this))
                    : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this));
                break;
            /* Does nothing for this layer (Dismiss IPV6 for this version...)
            case 6:
            */
            default:
                l_NextLayer = new PayloadLayer(payload, payloadLen, this);
        }
    }
    
}