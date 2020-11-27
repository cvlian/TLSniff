/* layer-tcp.cpp
 * 
 * routines for the TCP packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include "layer-tcp.h"
#include "layer-data.h"

namespace pump
{

    void TcpLayer::dissectData()
    {
        size_t hdr_len = getHeaderLen();
        if (l_datalen <= hdr_len)
            return;

        uint8_t* payload = l_data + hdr_len;
        size_t payloadLen = l_datalen - hdr_len;
        
        // In TLSniff, we don't need to parse the upper-layer (e.g., HTTP, SMTP, TLS, etc) of current one 
        l_nextlayer = new DataLayer(payload, payloadLen, this);
    }

    bool TcpLayer::isValidLayer(const uint8_t* data, size_t datalen)
    {
        const tcp_hdr* hdr = reinterpret_cast<const tcp_hdr*>(data);
        return datalen >= sizeof(tcp_hdr)
        && hdr->dataoffset >= 5
        && datalen >= hdr->dataoffset * sizeof(uint32_t);
    }

}