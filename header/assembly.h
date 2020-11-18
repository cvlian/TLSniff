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
#include "layer-ip4.h"
#include "layer-tcp.h"

/* TLS session Flags */
#define F_SAW_SYN                0x0001
#define F_SAW_SYNACK             0x0002
#define F_END_TCP_HS             0x0004
#define F_SAW_FIN                0x0008
#define F_LOST_CLIENTHELLO       0x0010
#define F_LOST_SERVERHELLO       0x0020

/* TCP analysis flags */
#define TCP_ZERO_WINDOW_PROBE       0x01
#define TCP_LOST_PACKET             0x02
#define TCP_KEEP_ALIVE              0x04
#define TCP_WINDOW_UPDATE           0x08
#define TCP_RETRANSMISSION          0x10

static const uint32_t IN_LIMIT = 1073741824u;
static const uint32_t FNV_PRIME = 16777619u;
static const uint32_t OFFSET_BASIS = 2166136261u;
static const int maxbuf = 262144;
static const long MEMORY_LIMIT = 8*1024*1024;

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

typedef std::pair<uint32_t, uint32_t> seqack;

namespace pump
{

    struct ScalarBuffer
    {
        uint8_t* buffer;
        size_t len;
    };

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
        uint32_t pos;
        uint16_t len;
        uint8_t hd[5];
    };

    struct Host {
        uint32_t IP;
        uint16_t Port;
        uint16_t win;
        uint32_t seq;
        uint32_t ack;
        uint16_t rcd_cnt;
        std::set<uint32_t> outoforderSeqs;
        std::set<uint32_t> previousSeqs;
        std::map<uint32_t, seqack> rootSeqAck;
        std::map<uint32_t, RecordPointer> rcdPointers;
    };

    struct Stream {
        uint16_t tlsFlags;
        uint32_t baseseq;
        uint32_t baseack;
        struct Host client;
        struct Host server;
    };

    void print_progressM(uint32_t c);

    void print_progressA(uint32_t s, uint32_t ts);

    void writeTLSrecord(const char* dir, int ss_idx, bool peer, uint32_t rootSeq);

    uint32_t parseIPV4string(const char* ipAddress);

    uint32_t fnv_hash(ScalarBuffer vec[], size_t vecSize);

    uint32_t hashStream(pump::Packet* packet);

    int64_t time_diff(struct timeval* etv, struct timeval* stv);

    void time_update(struct timeval* tv1, struct timeval* tv2);

    class Assembly
    {

        private:

            uint32_t ab_PacketCount;
            uint32_t ab_StreamCount;
            uint32_t ab_RecordCount;
            uint64_t ab_TotalByte;

            bool ab_shouldStop;

            struct timeval init_tv, base_tv, print_tv;

            std::map<uint32_t, int> ab_FlowTable;

            std::map<uint32_t, bool> ab_TcpFlowTable;

            std::map<uint32_t, Stream> streams;

            int addNewStream();

            int getStreamNumber(pump::Packet* packet);

            bool isTcpSyn(pump::Packet* packet);

        public:

            Assembly(timeval tv);

            ~Assembly();

            void registerEvent();

            uint32_t getTotalPacket() { return ab_PacketCount; };

            uint32_t getTotalStream() { return ab_StreamCount; }

            uint32_t getTotalRecord() { return ab_RecordCount; }

            uint64_t getTotalByteLen() { return ab_TotalByte; }

            timeval* getStartTime() { return &init_tv; } 

            bool isTerminated() {return ab_shouldStop; }

            void parsePacket(pump::Packet* packet, struct CaptureConfig* config);

            void managePacket(pump::Packet* packet, struct CaptureConfig* config);

            void mergeRecord(struct CaptureConfig* config);

    };

}

#endif