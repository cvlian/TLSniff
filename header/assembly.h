/* assembly.h
 * 
 * routines to extract SSL/TLS records
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_ASSEMBLY
#define PUMP_ASSEMBLY

#include <stdint.h>

#include <map>
#include <set>
#include <string>
#include <utility>

#include "packet.h"
#include "layer-ip.h"
#include "layer-tcp.h"


#define F_SAW_SYN              0x1
#define F_SAW_SYNACK           0x2
#define F_END_SYN_HS           0x4
#define F_END_FIN_HS           0x8
#define F_BASE_SEQ_SET        0x10
#define F_LOST_HELLO          0x20
#define F_FRAME_OVERLAP       0x40

#define TCP_A_ACK_LOST_PACKET                0x1
#define TCP_A_DUPLICATE_ACK                  0x2
#define TCP_A_KEEP_ALIVE                     0x4
#define TCP_A_KEEP_ALIVE_ACK                 0x8
#define TCP_A_LOST_PACKET                   0x10
#define TCP_A_FAST_RETRANSMISSION           0x20
#define TCP_A_OUT_OF_ORDER                  0x40
#define TCP_A_SPURIOUS_RETRANSMISSION       0x80
#define TCP_A_RETRANSMISSION               0x100
#define TCP_A_WINDOW_FULL                  0x200
#define TCP_A_WINDOW_UPDATE                0x400
#define TCP_A_ZERO_WINDOW                  0x800
#define TCP_A_ZERO_WINDOW_PROBE           0x1000
#define TCP_A_ZERO_WINDOW_PROBE_ACK       0x2000
#define TCP_A_NON_RECORD                  0x4000

#define MAX_RECORD_LEN       0x4800
#define MAX_QUEUE_CAPACITY       50

static const std::map<uint8_t, std::string> recordType = {
    { 20, "Change Cipher Spec" },
    { 21, "Alert" },
    { 22, "Handshake" },
    { 23, "Application Data" }
};

static const std::map<uint8_t, std::string> handshakeType = {
    { 0, "(hello request)"},
    { 1, "(client hello)"},
    { 2, "(server hello)"},
    { 3, "(hello verify request)"},
    { 4, "(new session ticket)"},
    { 5, "(end of early data)"},
    { 6, "(hello retry request)"},
    { 8, "(encrypted extensions)"},
    { 11, "(certificate)"},
    { 12, "(server key exchange)"},
    { 13, "(certificate request)"},
    { 14, "(server hello done)"},
    { 15, "(certificate verify)"},
    { 16, "(client key exchange)"},
    { 20, "(finished)"},
    { 21, "(certificate url)"},
    { 22, "(certificate status)"},
    { 23, "(supplemental data)"},
    { 24, "(key update)"},
    { 25, "(compressed certificate)"}
};

namespace pump
{

    struct CaptureConfig
    {
        uint32_t maxPacket;
        uint32_t maxTime;
        uint32_t maxRcd;
        uint32_t maxRcdpf;
        bool outputTypeHex;
        bool quitemode;
        std::string outputFileTo;
    };

    struct RecordPointer{
        uint16_t pos;
        uint16_t len;
        uint8_t hd[5];
    };

    struct SegInfo{
        uint32_t seq = 0;
        uint16_t seglen = 0;
        bool is_newrcd = false;

        bool operator<(const SegInfo& other) const
        {
            return (seq < other.seq);
        }

        bool operator==(const SegInfo& other) const
        {
            return (seq == other.seq);
        }
    };

    struct Flow {
        uint32_t ip = 0;
        uint16_t port = 0;
        uint32_t win = 0xFFFFFFFF;
        uint32_t baseseq = 0;
        uint16_t flags = 0;
        uint16_t a_flags = 0;
        uint32_t nextseq = 0;
        uint32_t lastack = 0;
        uint16_t rcd_cnt = 0;
        uint16_t rcd_idx = 0;
        RecordPointer rcd_pt = {0,0,{}};
        std::set<SegInfo> reserved_seq = {};
    };

    struct Stream {
        Flow client;
        Flow server;
    };

    uint32_t hashStream(pump::Packet* packet);

    bool isTcpSyn(pump::Packet* packet);

    bool isClient(pump::Packet* packet, Stream* ss);

    bool isTLSrecord(uint8_t* data, uint32_t seglen);

    bool isSSLv2record(uint8_t* data, uint32_t seglen);

    class Assembly
    {

        private:

            uint32_t ab_pkt_cnt;
            uint32_t ab_flow_cnt;
            uint32_t ab_rcd_cnt;
            uint64_t ab_totalbytes;

            bool ab_stop;

            struct timeval ab_init_tv, ab_base_tv, ab_print_tv;

            std::map<uint32_t, int> ab_flowtable;

            std::map<uint32_t, bool> ab_initiated;

            std::map<uint32_t, Stream> ab_smap;

            int addNewStream(pump::Packet* packet);

            int getStreamNumber(pump::Packet* packet);

            void writeTLSrecord(const char* dir, int idx, bool peer);

            void cleanOldPacket(const char* dir, int idx, bool peer, Flow* fwd, CaptureConfig* config);

            void parseReservedPacket(const char* dir, int idx, bool peer, uint32_t seq, CaptureConfig* config);

        public:

            Assembly(timeval tv);

            ~Assembly();

            void registerEvent();

            uint32_t getTotalPacket() { return ab_pkt_cnt; };

            uint32_t getTotalStream() { return ab_flow_cnt; }

            uint32_t getTotalRecord() { return ab_rcd_cnt; }

            uint64_t getTotalByteLen() { return ab_totalbytes; }

            timeval* getStartTime() { return &ab_init_tv; } 

            bool isTerminated() {return ab_stop; }

            void parsePacket(pump::Packet* packet, CaptureConfig* config);

            void managePacket(pump::Packet* packet, CaptureConfig* config);

            void mergeRecord(CaptureConfig* config);

            void close();

    };

}

#endif