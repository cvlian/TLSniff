/* layer-payload.cpp
 * 
 * routines for the data packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include <string.h>

#include "layer-payload.h"

namespace pump
{

    PayloadLayer::PayloadLayer(const uint8_t* data, size_t dataLen, bool dummy) : Layer()
    {
        l_Data = new uint8_t[dataLen];
        memcpy(l_Data, data, dataLen);
        l_DataLen = dataLen;
        l_Protocol = PROTO_Payload;
    }
    
}
