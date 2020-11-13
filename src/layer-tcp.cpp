/* layer-tcp.cpp
 * 
 * routines for the TCP packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include "layer-tcp.h"
#include "layer-payload.h"

namespace pump
{

    void TcpLayer::parseNextLayer()
    {
        size_t headerLen = getHeaderLen();
        if (l_DataLen <= headerLen)
            return;

        uint8_t* payload = l_Data + headerLen;
        size_t payloadLen = l_DataLen - headerLen;
        
        // In TLSniff, we don't need to parse the upper-layer (e.g., HTTP, SMTP, TLS, etc) of current one 
        // Such thing will be done in the "assembly" class
        l_NextLayer = new PayloadLayer(payload, payloadLen, this);
    }

}