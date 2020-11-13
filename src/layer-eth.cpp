/* layer-eth.cpp
 * 
 * routines for the ethernet packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include <string.h>
#include <arpa/inet.h>

#include "layer-eth.h"
#include "layer-ip4.h"
#include "layer-mpls.h"
#include "layer-vlan.h"
#include "layer-pppoe.h"
#include "layer-payload.h"

namespace pump
{
    
    void Eth2Layer::parseNextLayer()
    {
        if (l_DataLen <= sizeof(ether2_header))
            return;

        ether2_header* hdr = getEthHeader();
        uint8_t* payload = l_Data + sizeof(ether2_header);
        size_t payloadLen = l_DataLen - sizeof(ether2_header);

        switch (be16toh(hdr->etherType))
        {
            case ETHERTYPE_IP:
                l_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
                    ? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this))
                    : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this));
                break;
            /* Does nothing for this layer (Dismiss IPV6 for this version...)
            case ETHERTYPE_IPV6:
            */
            /* Does nothing for this layer (ArpLayer can't have TLS records)
            case ETHERTYPE_ARP:
            */
            case ETHERTYPE_VLAN:
                l_NextLayer = new VlanLayer(payload, payloadLen, this);
                break;
            case ETHERTYPE_PPPOES:
                l_NextLayer = PPPoESessionLayer::isDataValid(payload, payloadLen)
                    ? static_cast<Layer*>(new PPPoESessionLayer(payload, payloadLen, this))
                    : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this));
                break;
            /* Does nothing for this layer (PPPoEDiscoveryLayer can't have TLS records) 
            case ETHERTYPE_PPPOED:
            */
            case ETHERTYPE_MPLS:
                l_NextLayer = new MplsLayer(payload, payloadLen, this);
                break;
            default:
                l_NextLayer = new PayloadLayer(payload, payloadLen, this);
        }
    }

    void Eth802_3Layer::parseNextLayer()
    {
        if (l_DataLen <= sizeof(ether802_3_header))
            return;

        uint8_t* payload = l_Data + sizeof(ether802_3_header);
        size_t payloadLen = l_DataLen - sizeof(ether802_3_header);

        l_NextLayer = new PayloadLayer(payload, payloadLen, this);
    }

}