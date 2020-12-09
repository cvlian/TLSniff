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


/* Flow status */
#define F_SAW_SYN              0x1
#define F_SAW_SYNACK           0x2
#define F_END_SYN_HS           0x4
#define F_END_FIN_HS           0x8
#define F_BASE_SEQ_SET        0x10
#define F_LOST_HELLO          0x20
#define F_FRAME_OVERLAP       0x40

/* TCP packet status */
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

static const std::map<uint8_t, std::pair<std::string, uint8_t>> recordType = {
    { 20, { "Change Cipher Spec", 18 } },
    { 21, { "Alert", 5 } },
    { 22, { "Handshake", 9 } },
    { 23, { "Application Data", 16 } }
};

static const std::map<uint8_t, std::pair<std::string, uint8_t>> handshakeType = {
    { 0,  { "(hello request)", 15} },
    { 1,  { "(client hello)", 14} },
    { 2,  { "(server hello)", 14} },
    { 3,  { "(hello verify request)", 22} },
    { 4,  { "(new session ticket)", 20} },
    { 5,  { "(end of early data)", 19} },
    { 6,  { "(hello retry request)", 21} },
    { 8,  { "(encrypted extensions)", 22} },
    { 11, { "(certificate)", 13} },
    { 12, { "(server key exchange)", 21} },
    { 13, { "(certificate request)", 21} },
    { 14, { "(server hello done)", 19} },
    { 15, { "(certificate verify)", 20} },
    { 16, { "(client key exchange)", 21} },
    { 21, { "(certificate url)", 17} },
    { 22, { "(certificate status)", 20} },
    { 23, { "(supplemental data)", 19} },
    { 24, { "(key update)", 12} },
    { 25, { "(compressed certificate)", 24} }
};

namespace pump
{

    /* Data structure to hold capture preferences */
    struct CaptureConfig
    {
        uint32_t maxPacket;         /* Maximum #packets to be captured */  
        uint32_t maxTime;           /* Duration limit */
        uint32_t maxRcd;            /* Maximum #records to be captured*/
        uint32_t maxRcdpf;          /* Maximum #records extracted per flow */
        bool outputTypeHex;         /* When set, user will get results in hexadecimal format */
        bool quitemode;             /* When set, do not display record exchange processes*/
        std::string outputFileTo;   /* Output file for the data to be written */
    };

    /* Data structure to address record parsing routines */
    struct RecordPointer{
        uint16_t rcd_len;           /* Record length */
        uint16_t rcd_pos;           /* Current position of pointer reading record data */
        uint16_t hs_len;            /* Handshake length */
        uint16_t hs_pos;            /* Current position of pointer reading handshake data */
        uint8_t prev_rcd_type;      /* Previous record type */
        uint8_t hd[9];              /* First 9 bytes filed of record */
    };

    /* This structure contains segment boundary infos */
    struct SegInfo{
        uint32_t seq = 0;           /* Sequence number */
        uint16_t seglen = 0;        /* Segment length */
        bool is_newrcd = false;     /* True, if a new record header starts at the first position */

        bool operator<(const SegInfo& other) const
        {
            return (seq < other.seq);
        }

        bool operator==(const SegInfo& other) const
        {
            return (seq == other.seq);
        }
    };

    /* Data structure that keeps flow data */
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
        RecordPointer rcd_pt = {0,0,0,0,0,{}};
        std::set<SegInfo> reserved_seq = {};
    };

    /* Data structure that keeps bidirectional flow infos */
    struct Stream {
        Flow client;
        Flow server;
    };

    uint32_t hashStream(pump::Packet* packet);

    bool isTcpSyn(pump::Packet* packet);

    bool isClient(pump::Packet* packet, Stream* ss);

    bool isTLSrecord(uint8_t* data, uint32_t seglen);

    bool isSSLv2record(uint8_t* data, uint32_t seglen);

    bool isUnencryptedHS(uint8_t curr_rcd_type, uint8_t prev_rcd_type);

    class Assembly
    {

        private:

            uint32_t ab_pkt_cnt;
            uint32_t ab_flow_cnt;
            uint32_t ab_rcd_cnt;
            uint64_t ab_totalbytes;

            bool ab_stop;

            struct timeval ab_init_tv, ab_print_tv;

            std::map<uint32_t, int> ab_flowtable;

            std::map<uint32_t, bool> ab_initiated;

            std::map<uint32_t, Stream> ab_smap;

            int addNewStream(pump::Packet* packet);

            int getStreamNumber(pump::Packet* packet);

            void writeTLSrecord(int idx, bool peer);

            void displayTLSrecord(Stream* ss, bool peer, uint8_t rcd_type, uint8_t hs_type);

            void cleanOldPacket(int idx, bool peer, Flow* fwd, CaptureConfig* config);

            void parseReservedPacket(int idx, bool peer, uint32_t seq, CaptureConfig* config);

        public:

            Assembly(timeval tv);

            ~Assembly();

            void registerEvent();

            uint32_t getTotalPacket() { return ab_pkt_cnt; };

            uint32_t getTotalStream() { return ab_flow_cnt; }

            uint32_t getTotalRecord() { return ab_rcd_cnt; }

            uint64_t getTotalByteLen() { return ab_totalbytes; }

            bool isTerminated() {return ab_stop; }

            void parsePacket(pump::Packet* packet, CaptureConfig* config);

            void managePacket(pump::Packet* packet, CaptureConfig* config);

            void mergeRecord(CaptureConfig* config);

            void close();

    };

}

#endif