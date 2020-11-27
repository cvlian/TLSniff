/* layer-tcp.h
 *
 * routines for the TCP packet parsing
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_LAYER_TCP
#define PUMP_LAYER_TCP

#include "layer.h"

#define TCPOPT_EOL              0
#define TCPOPT_NOP              1
#define TCPOPT_MSS              2
#define TCPOPT_WINSCALE         3
#define TCPOPT_SACK_PERM        4
#define TCPOPT_SACK             5
#define TCPOPT_TIMESTAMP        8
#define TCPOPT_TCHECK           18
#define TCPOPT_SCPS             20
#define TCPOPT_SNACK            21
#define TCPOPT_RECBOUND         22
#define TCPOPT_CORREXP          23
#define TCPOPT_SNAP             24
#define TCPOPT_COMFILTER        26
#define TCPOPT_QS               27
#define TCPOPT_USER_TO          28
#define TCPOPT_AUOP             29
#define TCPOPT_MPTCP            30
#define TCPOPT_FASTCOOKIE       34
#define TCPOPT_ENNEGO           69
#define TCPOPT_EXP_FD           253
#define TCPOPT_EXP_FE           254
#define TCPOPT_Unknown          255

namespace pump
{

    typedef struct _tcp_hdr 
    {
        uint16_t sport;  
        uint16_t dport;
        uint32_t rawseq;
        uint32_t rawack;
        uint16_t reserved:4,
                 dataoffset:4,
                 flag_fin:1,
                 flag_syn:1,
                 flag_rst:1,
                 flag_psh:1,
                 flag_ack:1,
                 flag_urg:1,
                 flag_ece:1,
                 flag_cwr:1;
        uint16_t rawwin;
        uint16_t checksum;
        uint16_t urg_pt;
    } tcp_hdr;

    class TcpLayer : public Layer
    {

        public:

            TcpLayer(uint8_t* data, size_t datalen, Layer* prev_layer) : Layer(data, datalen, prev_layer) { l_proto = PROTO_TCP; }

            virtual ~TcpLayer() {};

            void dissectData();

            tcp_hdr* getHeader() const { return (tcp_hdr*)l_data; }

            size_t getHeaderLen() const { return getHeader()->dataoffset*4; }

            static bool isValidLayer(const uint8_t* data, size_t datalen);

    };
    
}

#endif