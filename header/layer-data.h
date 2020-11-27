/* layer-data.h
 *
 * routines for the data packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_DATA
#define PUMP_LAYER_DATA

#include "layer.h"

namespace pump
{

    class DataLayer : public Layer
    {

        public:

            DataLayer(uint8_t* data, size_t datalen, Layer* prev_layer) : Layer(data, datalen, prev_layer) { l_proto = PROTO_DATA; }

            virtual ~DataLayer() {};

            void dissectData() {}

            size_t getHeaderLen() const { return l_datalen; }

    };

    class TrailerLayer : public Layer
    {

        public:

            TrailerLayer(uint8_t* data, size_t datalen, Layer* prev_layer) : Layer(data, datalen, prev_layer) { l_proto = PROTO_TRAILER; }

            virtual ~TrailerLayer() {};

            void dissectData() {}

            size_t getHeaderLen() const { return l_datalen; }

    };
    
}

#endif