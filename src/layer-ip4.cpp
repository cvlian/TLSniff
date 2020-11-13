/* layer-ip4.cpp
 * 
 * routines for the IPv4 packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include "layer-gre.h"
#include "layer-ip4.h"
#include "layer-tcp.h"
#include "layer-payload.h"

namespace pump
{

    IPv4Address::IPv4Address(const std::string& addrAsString)
    {
        if (inet_pton(AF_INET, addrAsString.data(), ad_Bytes) <= 0)
            memset(ad_Bytes, 0, sizeof(ad_Bytes));
    }

    std::string IPv4Address::toString() const
    {
        char addrBuffer[INET_ADDRSTRLEN];

        if (inet_ntop(AF_INET, toBytes(), addrBuffer, sizeof(addrBuffer)) != NULL)
            return std::string(addrBuffer);

        return std::string();
    }

    IPv4Layer::IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer)
    {
        l_Protocol = PROTO_IPv4;
        size_t totalLen = ntohs(getIPv4Header()->totalLength);

        if ((totalLen < l_DataLen) && (totalLen !=0))
            l_DataLen = totalLen;

    }

    bool IPv4Layer::isFragment() const
    {
        return ((getFragmentFlags() & IP_MORE_FRAGMENTS) != 0 || getFragmentOffset() != 0);
    }

    uint8_t IPv4Layer::getFragmentFlags() const
    {
        return getIPv4Header()->fragmentOffset & 0xE0;
    }

    uint16_t IPv4Layer::getFragmentOffset() const
    {
        return be16toh(getIPv4Header()->fragmentOffset & (uint16_t)0xFF1F) * 8;
    }

    void IPv4Layer::parseNextLayer()
    {

        size_t hdrLen = getHeaderLen();
        if (l_DataLen <= hdrLen)
            return;

        iphdr* ipHdr = getIPv4Header();

        uint64_t greVer = PROTO_UnknownProtocol;

        uint8_t ipVersion = 0;

        uint8_t* payload = l_Data + hdrLen;
        size_t payloadLen = l_DataLen - hdrLen;

        if (isFragment())
        {
            l_NextLayer = new PayloadLayer(payload, payloadLen, this);
            return;
        }

        switch (ipHdr->protocol)
        {
            /* Does nothing for this layer (Dismiss ICMP for this version...)
            case IPV4PROTO_UDP:
            */
            case IPV4PROTO_TCP:
                l_NextLayer = TcpLayer::isDataValid(payload, payloadLen)
                    ? static_cast<Layer*>(new TcpLayer(payload, payloadLen, this))
                    : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this));
                break;
            /* Does nothing for this layer (Dismiss ICMP for this version...)
            case IPV4PROTO_ICMP:
            */
            case IPV4PROTO_IPIP:
                ipVersion = *payload >> 4;
                if (ipVersion == 4)
                    l_NextLayer = new IPv4Layer(payload, payloadLen, this);
                /* Does nothing for this layer (Dismiss IPV6 for this version...)
                else if (ipVersion == 6)
                */
                else
                    l_NextLayer = new PayloadLayer(payload, payloadLen, this);
                break;
            case IPV4PROTO_GRE:
                greVer = GreLayer::getGREVersion(payload, payloadLen);
                if (greVer == PROTO_GREv0)
                    l_NextLayer = new GREv0Layer(payload, payloadLen, this);
                else if (greVer == PROTO_GREv1)
                    l_NextLayer = new GREv1Layer(payload, payloadLen, this);
                else
                    l_NextLayer = new PayloadLayer(payload, payloadLen, this);
                break;
            /* Does nothing for this layer (IGMP can't have TLS records)
            case IPV4PROTO_IGMP:
            */
            default:
                l_NextLayer = new PayloadLayer(payload, payloadLen, this);
        }
    }

    in_addr* sockaddr2in_addr(struct sockaddr* sa)
    {
        if (sa == NULL)
            return NULL;
        if (sa->sa_family == AF_INET)
            return &(((struct sockaddr_in*)sa)->sin_addr);
        return NULL;
    }

    void sockaddr2string(struct sockaddr* sa, char* resultString)
    {
        in_addr* ipv4Addr = sockaddr2in_addr(sa);
        if (ipv4Addr != NULL)
        {
            inet_ntop(AF_INET, &(((sockaddr_in*)sa)->sin_addr), resultString, INET_ADDRSTRLEN);
        }
        else
        {
            inet_ntop(AF_INET6, &(((sockaddr_in6*)sa)->sin6_addr), resultString, INET6_ADDRSTRLEN);
        }
    }

}