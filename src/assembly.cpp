/* assembly.cpp
 * 
 * routines to extract SSL/TLS records
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include <stdio.h>
#include <dirent.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <sys/resource.h>

#include "handler.h"
#include "assembly.h"

namespace pump
{
    
    char pktBUF[maxbuf];
    char nameBUF[512];
    struct timeval curr_tv;

    static void onInterrupted(void* cookie)
    {
        bool* shouldStop = (bool*)cookie;
        *shouldStop = true;
    }

    void stop_signal_callback_handler(int signum) {
        printf("\n**All Stop**================================================\n");
        clearTLSniff();
        exit(signum);
    }

    void print_progressM(uint32_t c)
    {
        printf("\r**Split TCP stream**======================================== (%u)", c);
        fflush(stdout);
    }

    void print_progressA(uint32_t s, uint32_t ts)
    {
        printf("\r**Merge TCP stream**======================================== (%d/%d) ", s, ts);
        fflush(stdout);
    }

    void writeTLSrecord(const char* dir, int idx, bool peer, uint32_t Seq, uint32_t Ack)
    {
        sprintf(nameBUF, "%s%u/%.10d%.10d%c", dir, idx, (peer ? Seq : Ack), (peer ? Ack : Seq), (peer ? 'C' : 'S'));
        FILE* fp = fopen(nameBUF, "a");

        if (fp == NULL)
            EXIT_WITH_RUNERROR("###ERROR : an error occurs while writting record data");

        fprintf(fp, "%s", pktBUF);
        fclose(fp);
    }

    uint32_t parseIPV4string(const char* ipAddress) 
    {
        unsigned char ipbytes[4];
        sscanf(ipAddress, "%hhu.%hhu.%hhu.%hhu", &ipbytes[3], &ipbytes[2], &ipbytes[1], &ipbytes[0]);
        return ipbytes[0] | ipbytes[1] << 8 | ipbytes[2] << 16 | ipbytes[3] << 24;
    }

    uint32_t fnv_hash(ScalarBuffer vec[], size_t vecSize)
    {
        uint32_t hash = OFFSET_BASIS;
        for (size_t i = 0; i < vecSize; ++i)
        {
            for (size_t j = 0; j < vec[i].len; ++j)
            {
                hash *= FNV_PRIME;
                hash ^= vec[i].buffer[j];
            }
        }
        return hash;
    }

    uint32_t hashStream(pump::Packet* packet)
    {
        struct ScalarBuffer vec[5];

        uint16_t portSrc = 0;
        uint16_t portDst = 0;
        int srcPosition = 0;

        pump::TcpLayer* tcpLayer = packet->getLayerOfType<pump::TcpLayer>();
        portSrc = tcpLayer->getTcpHeader()->portSrc;
        portDst = tcpLayer->getTcpHeader()->portDst;

        if (portDst < portSrc)
        {
            srcPosition = 1;
        }

        vec[0 + srcPosition].buffer = (uint8_t*)&portSrc;
        vec[0 + srcPosition].len = 2;
        vec[1 - srcPosition].buffer = (uint8_t*)&portDst;
        vec[1 - srcPosition].len = 2;

        pump::IPv4Layer* ipv4Layer = packet->getLayerOfType<pump::IPv4Layer>();

        if (portSrc == portDst && ipv4Layer->getIPv4Header()->ipDst < ipv4Layer->getIPv4Header()->ipSrc)
        {
            srcPosition = 1;
        }

        vec[2 + srcPosition].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipSrc;
        vec[2 + srcPosition].len = 4;
        vec[3 - srcPosition].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipDst;
        vec[3 - srcPosition].len = 4;
        vec[4].buffer = &(ipv4Layer->getIPv4Header()->protocol);
        vec[4].len = 1;

        return fnv_hash(vec, 5);
    }    

    int64_t time_diff(struct timeval* etv, struct timeval* stv)
    {
        int64_t dif = 1000000 * (int64_t)(etv->tv_sec - stv->tv_sec) + (int64_t)etv->tv_usec - (int64_t)stv->tv_usec;
        // Negative delta time from previous captured frame -> out of order
        if(dif < 0) return -1;

        return dif;
    }

    void time_update(struct timeval* tv1, struct timeval* tv2)
    {
        tv1->tv_usec = tv2->tv_usec;
        tv1->tv_sec = tv2->tv_sec;
    }

    bool Assembly::isTcpSyn(pump::Packet* packet)
    {
        if (packet->isPacketOfType(PROTO_TCP))
        {

            pump::TcpLayer* tcpLayer = packet->getLayerOfType<pump::TcpLayer>();

            bool isSyn = (tcpLayer->getTcpHeader()->synFlag == 1);
            bool isNotAck = (tcpLayer->getTcpHeader()->ackFlag == 0);

            // return true only if it's a pure SYN packet (and not SYN/ACK)
            return (isSyn && isNotAck);
        }

        return false;
    }

    Assembly::Assembly(timeval tv) : base_tv((struct timeval){ 0 }), print_tv((struct timeval){ 0 }), ab_FlowTable(), ab_TcpFlowTable(), streams() 
	{
        init_tv = tv;
        ab_PacketCount = 0;
        ab_StreamCount = 0;
        ab_RecordCount = 0;
        ab_TotalByte = 0;
        registerEvent();
	}

    Assembly::~Assembly() 
	{
        ab_FlowTable.clear();
        ab_TcpFlowTable.clear();
        streams.clear();
	}

    void Assembly::registerEvent()
    {
        ab_shouldStop = false;
        pump::EventHandler::getInstance().onInterrupted(onInterrupted, &ab_shouldStop);
    }

    int Assembly::addNewStream()
    {
        struct Host client = {0, 0, 0xffff, 0, 0, 0, {}, {}, {}, {}};
        struct Host server = {0, 0, 0xffff, 0, 0, 0, {}, {}, {}, {}};

        struct Stream ss = {
            .tlsFlags = 0,
            .baseseq = 0,
            .baseack = 0,
            .client = client,
            .server = server
            };

        streams[ab_StreamCount] = ss;

        std::string sd = saveDir + std::to_string(ab_StreamCount) + "/";

        if(access(sd.c_str(), 0) == -1)
            mkdir(sd.c_str(), 0777);

        return ab_StreamCount++;
    }

    int Assembly::getStreamNumber(pump::Packet* packet)
    {

        uint32_t hash = hashStream(packet);

        bool isSyn = isTcpSyn(packet);

        if (ab_FlowTable.find(hash) == ab_FlowTable.end())
        {
            // We do not care about truncated flow
            if(!isSyn) return -1;

            ab_FlowTable[hash] = addNewStream();
            ab_TcpFlowTable[hash] = true;
        }
        else
        {
            if (isSyn && ab_TcpFlowTable.find(hash) != ab_TcpFlowTable.end() && ab_TcpFlowTable[hash] == false)
            {
                ab_FlowTable[hash] = addNewStream();
            }
            ab_TcpFlowTable[hash] = isSyn;
        }
        return ab_FlowTable[hash];
    }

    void Assembly::parsePacket(pump::Packet* packet, struct CaptureConfig* config)
    {

        if (!(packet->getProtocolTypes() & PROTO_TCP)
        || !((packet->getProtocolTypes()) & PROTO_IPv4)) return;

        int ss_idx = getStreamNumber(packet);

        if(ss_idx == -1) return;

        struct Stream* ss = &(streams[ss_idx]);

        uint32_t srcIP = parseIPV4string(packet->getLayerOfType<pump::IPv4Layer>()->getSrcIpAddress().toString().c_str());
        uint32_t dstIP = parseIPV4string(packet->getLayerOfType<pump::IPv4Layer>()->getDstIpAddress().toString().c_str());
        uint16_t srcport = (uint16_t)ntohs(packet->getLayerOfType<pump::TcpLayer>()->getTcpHeader()->portSrc);
        uint16_t dstport = (uint16_t)ntohs(packet->getLayerOfType<pump::TcpLayer>()->getTcpHeader()->portDst);

        uint32_t seqnum = packet->getLayerOfType<pump::TcpLayer>()->getTcpHeader()->sequenceNumber;
        uint32_t acknum = packet->getLayerOfType<pump::TcpLayer>()->getTcpHeader()->ackNumber;
        uint16_t window = packet->getLayerOfType<pump::TcpLayer>()->getTcpHeader()->windowSize;
        seqnum = ((seqnum & 0xff000000) >> 24) + ((seqnum & 0xff0000) >> 8) + ((seqnum & 0xff00) << 8) + ((seqnum & 0xff) << 24);
        acknum = ((acknum & 0xff000000) >> 24) + ((acknum & 0xff0000) >> 8) + ((acknum & 0xff00) << 8) + ((acknum & 0xff) << 24);

        bool isFIN = (packet->getLayerOfType<pump::TcpLayer>()->getTcpHeader()->finFlag == 1);
        bool isSYN = (packet->getLayerOfType<pump::TcpLayer>()->getTcpHeader()->synFlag == 1);
        bool isRST = (packet->getLayerOfType<pump::TcpLayer>()->getTcpHeader()->rstFlag == 1);
        bool isACK = (packet->getLayerOfType<pump::TcpLayer>()->getTcpHeader()->ackFlag == 1);

        if(!(ss->tlsFlags & F_SAW_SYN))
        {
            ss->client.IP = srcIP;
            ss->client.Port = srcport;
            ss->server.IP = dstIP;
            ss->server.Port = dstport;
            
            ss->baseseq = seqnum;
            ss->tlsFlags |= F_SAW_SYN; 
        }

        bool peer = (ss->client.IP == srcIP);
        size_t paylen = packet->getLayerOfType<pump::TcpLayer>()->getLayerPayloadSize();

        if(!(ss->tlsFlags & F_SAW_SYNACK) && isACK)
        {
            ss->baseack = seqnum;
            ss->tlsFlags |= F_SAW_SYNACK;
        }

        // Get relative seq/ack numbers
        seqnum -= (peer ? ss->baseseq : ss->baseack);
        acknum -= (peer ? ss->baseack : ss->baseseq);

        uint32_t nextseq = seqnum + paylen;

        if (isSYN || isFIN)
        {
            nextseq += 1;
        }

        if(!(ss->tlsFlags & F_END_TCP_HS)
        && isACK 
        && paylen == 0 
        && seqnum == 1 
        && acknum == 1){
            ss->tlsFlags |= F_END_TCP_HS;
        }

        struct Host* fwd = &(peer ? ss->client : ss->server);
        struct Host* rev = &(peer ? ss->server : ss->client);

        if(fwd->rcd_cnt + rev->rcd_cnt >= config->maxRcdpf) return;

        uint8_t TCP_analysis = 0;

        // ZERO WINDOW PROBE
        if (paylen == 1
        && rev->win == 0
        && fwd->seq == seqnum){
            TCP_analysis |= TCP_ZERO_WINDOW_PROBE;
            WRITE_LOG("└─#ZERO WINDOW PROBE : %d", ab_PacketCount);
            goto SeqUpdate;
        }

        // KEEP ALIVE
        if (paylen <= 1
        && !(isFIN || isSYN || isRST)
        && fwd->seq - 1 == seqnum){
            TCP_analysis |= TCP_KEEP_ALIVE;
            WRITE_LOG("└─#KEEP ALIVE : %d", ab_PacketCount);
            goto SeqUpdate;
        }

        // RETRANSMISSION
        if ((paylen > 0 || isSYN || isFIN)
        && seqnum < fwd->seq
        && !(paylen > 1 && fwd->seq - 1  == seqnum)
        && fwd->previousSeqs.find(seqnum) != fwd->previousSeqs.end()){
            TCP_analysis |= TCP_RETRANSMISSION;
            WRITE_LOG("└─#RETRANSMISSION : %d", ab_PacketCount);
            return;
        }

        // LOST SEGMENT
        if (fwd->seq
        && seqnum > fwd->seq
        && !isRST){
            TCP_analysis |= TCP_LOST_PACKET;
            WRITE_LOG("└─#LOST SEGMENT : %d", ab_PacketCount);
        }

        SeqUpdate:

        fwd->win = window;
        fwd->ack = acknum;

        if (nextseq > fwd->seq || !fwd->seq)
        {
            if(!(TCP_analysis & TCP_ZERO_WINDOW_PROBE))
            {
                fwd->seq = nextseq;
            }
        }

        // TCP PACKETS WITHOUT RECORD DATA
        if(paylen == 0
	    || isSYN
	    || !(ss->tlsFlags & F_END_TCP_HS)
	    || (TCP_analysis & (TCP_ZERO_WINDOW_PROBE | TCP_KEEP_ALIVE))) return;

        fwd->previousSeqs.insert(seqnum);

        struct RecordPointer* rcdPointer;
        seqack rseqack;

        if (fwd->rootSeqAck.find(seqnum) != fwd->rootSeqAck.end())
        {
            rseqack = fwd->rootSeqAck[seqnum];
            rcdPointer = &(fwd->rcdPointers[rseqack.first]);
            WRITE_LOG("└──Read Record (continued) : %d (%d/%d)", ab_PacketCount, rcdPointer->pos, rcdPointer->len);
        }
        else
        {
            rseqack = seqack(seqnum, acknum);
            fwd->rootSeqAck[seqnum] = rseqack;
            fwd->rcdPointers[seqnum] = {0, 0, {}};
            rcdPointer = &(fwd->rcdPointers[seqnum]);
        }

        uint8_t* payld = packet->getLayerOfType<pump::TcpLayer>()->getLayerPayload();
        int p = 0;

        for(int i = 0; i < (int)paylen; i++)
        {
            if (rcdPointer->pos < 5)
            {
                rcdPointer->hd[(rcdPointer->pos)++] = *(payld + i);
                continue;
            }
            else if (rcdPointer->pos == 5)
            {
                // for SSL 2.0
                if(peer
                && rcdPointer->hd[0]/64 == 2
                && !(rcdPointer->hd[0]%64 == 0 && rcdPointer->hd[1] == 0)
                && rcdPointer->hd[2] == 1
                && rcdPointer->hd[3] == 3
                && rcdPointer->hd[4] <= 3){
                    rcdPointer->len = 256*(int)(rcdPointer->hd[0]%64) + (int)rcdPointer->hd[1] - 3;
                }
                // for SSL 3.0 ~ TLS 1.3
                else if(rcdPointer->hd[0] >= 20
                && rcdPointer->hd[0] <= 23
                && rcdPointer->hd[1] == 3
                && rcdPointer->hd[2] <= 3
                && !(rcdPointer->hd[3] == 0 && rcdPointer->hd[4] == 0)){

                    if (!(peer && fwd->rcd_cnt == 0 && (*(payld + i) != 1 || rcdPointer->hd[0] != 22)))
                    {
                        ss->tlsFlags |= F_LOST_CLIENTHELLO;
                    }
                    else if(!(!peer && fwd->rcd_cnt == 0 && (*(payld + i) != 2 || rcdPointer->hd[0] != 22)))
                    {
                        ss->tlsFlags |= F_LOST_SERVERHELLO;
                    }
                    rcdPointer->len = 256*(int)rcdPointer->hd[3] + (int)rcdPointer->hd[4];
                }
                else
                {
                    rcdPointer->pos = 0;
                    if(TCP_analysis & TCP_LOST_PACKET)
                    {
                        fwd->outoforderSeqs.insert(seqnum);
                        sprintf(nameBUF, "%s%u/%.10dT%c", saveDir.c_str(), ss_idx, rseqack.first, (peer ? 'C' : 'S'));
                        FILE* fp = fopen(nameBUF, "w");
                        
                        if (fp == NULL)
                            EXIT_WITH_RUNERROR("###ERROR : encounter an error while writing the misplaced segment from %s : %d", nameBUF, ab_PacketCount);

                        fwrite(packet->getRawData(), packet->getRawDataLen(), 1, fp);
                        fclose(fp);
                        WRITE_LOG("└──WRITE TEMPORAL PAYLOAD DATA to %s : %d", nameBUF, ab_PacketCount);
                    }
                    break;
                }
                if(!(config->quitemode))
                {
                    char sIP[16], dIP[16];

                    sprintf(sIP, "%d.%d.%d.%d", (srcIP >> 24) & 0xFF, (srcIP >> 16) & 0xFF, (srcIP >>  8) & 0xFF, (srcIP) & 0xFF);
                    sprintf(dIP, "%d.%d.%d.%d", (dstIP >> 24) & 0xFF, (dstIP >> 16) & 0xFF, (dstIP >>  8) & 0xFF, (dstIP) & 0xFF);
                    
                    printf("[Client] %s:%d  ", (peer ? sIP : dIP), (peer ? srcport : dstport));
                    for (int j = strlen((peer ? sIP : dIP)); j < 15; j++) printf(" ");
                    uint16_t temp = (peer ? srcport : dstport);
                    for (; temp < 10000; temp *= 10) printf(" ");
                    if(!peer) printf("<"); 
                    uint16_t typelen = (recordType.at(rcdPointer->hd[0])).length() 
                        + (rcdPointer->hd[0] != 22 ? 0 : (handshakeType.find(*(payld + i)) == handshakeType.end() ? 11 : (handshakeType.at(*(payld + i))).length()));
                    for (int j = 0; j < (50-typelen)/2 + (!peer ? 0 : 1); j++) printf("-");
                    printf(" %s%s ", (recordType.at(rcdPointer->hd[0])).c_str(),
                        (rcdPointer->hd[0] != 22 ? "" : (handshakeType.find(*(payld + i)) == handshakeType.end() ? "(encrypted)" : (handshakeType.at(*(payld + i))).c_str())));
                    for (int j = 0; j < (50-typelen+1)/2 + (!peer ? 0 : -1); j++) printf("-");
                    if(peer) printf(">"); 
                    for (int j = strlen((peer ? dIP : sIP)); j < 15; j++) printf(" ");
                    temp = (peer ? dstport : srcport);
                    for (; temp < 10000; temp *= 10) printf(" ");
                    printf("%s:%d [Server]\n", (peer ? dIP : sIP), (peer ? dstport : srcport));
                }
                if(config->outputFileTo != "")
                {
                    sprintf(pktBUF+p, "%.2x,%.2x,%.2x,%.2x,%.2x", 
                        rcdPointer->hd[0], rcdPointer->hd[1], rcdPointer->hd[2], rcdPointer->hd[3], rcdPointer->hd[4]);
                    p += 14;
                }
            }
            if(config->outputFileTo != "")
            {
                sprintf(pktBUF+p, ",%.2x", *(payld + i));
                p += 3;
            }
            if(++(rcdPointer->pos) == rcdPointer->len + 5u)
            {
                rcdPointer->pos = 0;
                (fwd->rcd_cnt)++;
                ab_RecordCount++;
                if(config->outputFileTo != "")
                {
                    sprintf(pktBUF+(p++), "\n");
                    pktBUF[p] = '\0';
                    writeTLSrecord(saveDir.c_str(), ss_idx, peer, rseqack.first, rseqack.second);
                    p = 0;
                }
                WRITE_LOG("└──Read Record : %d (%d)", ab_PacketCount, rcdPointer->len);
                if(ab_RecordCount == config->maxRcd)
                {
                    raise(SIGINT);
                    return;
                }
                if(fwd->rcd_cnt + rev->rcd_cnt >= config->maxRcdpf) return;
            }
        }

        // Write the front part of a record
        if(rcdPointer->pos > 0)
        {
            if (p > 0)
            {
                if(config->outputFileTo != "")
                {
                    pktBUF[p] = '\0';
                    writeTLSrecord(saveDir.c_str(), ss_idx, peer, rseqack.first, rseqack.second);
                }
                WRITE_LOG("└──Read Record : %d, but it continues on next packet (%d/%d)", ab_PacketCount, rcdPointer->pos, rcdPointer->len);
            }
            else
            {
                WRITE_LOG("└──Maybe a part of record : %d, we should check on next packet (%d)", ab_PacketCount, rcdPointer->pos);
            }
            fwd->rootSeqAck[nextseq] = rseqack;
        }
        // if current payload includes trimmed records, the reserved packet with nextseq is not a part of TLS stream
        else
        {
            return;
        }

        if(fwd->outoforderSeqs.find(nextseq) == fwd->outoforderSeqs.end()) return;

        // If the next expected seq num is equal to the first reserved packet, there would be an out-of-order issue
        sprintf(nameBUF, "%s%u/%.10dT%c", saveDir.c_str(), ss_idx, nextseq, (peer ? 'C' : 'S'));
        FILE* fp = fopen(nameBUF, "r");
        
        if (fp == NULL)
            EXIT_WITH_RUNERROR("###ERROR : encounter an error while loading the misplaced segment from %s : %d", nameBUF, ab_PacketCount);

        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        uint8_t* pData = new uint8_t[fsize];
        size_t res = fread(pData, 1, fsize, fp);
        if (res != (size_t)fsize)
            EXIT_WITH_RUNERROR("###ERROR : encounter an error while reading the misplaced segment from %s : %d", nameBUF, ab_PacketCount);

        pump::Packet reservedPacket = pump::Packet(pData, fsize, packet->getPacketTimeStamp(), true);

        fwd->outoforderSeqs.erase(nextseq);


        parsePacket(&reservedPacket, config);
    }

    void Assembly::managePacket(pump::Packet* packet, struct CaptureConfig* config)
    {
        struct timeval ref_tv = packet->getPacketTimeStamp();
        uint32_t pk_len = packet->getRawDataLen();
        if(ab_PacketCount == 0) time_update(&(base_tv), &ref_tv);
        int64_t delta_time = time_diff(&ref_tv, &(base_tv));

        gettimeofday(&curr_tv, NULL);
        int64_t run_time = time_diff(&ref_tv, &(base_tv));

        if (ab_PacketCount >= config->maxPacket || run_time/1000000 >= (int64_t)config->maxTime)
        {
            raise(SIGINT);
            return;
        }

        ab_TotalByte += pk_len;
		ab_PacketCount++;

        if (delta_time == 0 || time_diff(&ref_tv, &(print_tv)) >= 31250)
        {
            struct rusage r_usage;
            getrusage(RUSAGE_SELF, &r_usage);
            if(r_usage.ru_maxrss > MEMORY_LIMIT)
                EXIT_WITH_RUNERROR("###ERROR : The process consume too much memory");

            if(config->quitemode) print_progressM(ab_PacketCount);
            time_update(&(print_tv), &ref_tv);
        }

        parsePacket(packet, config);

    }

    void Assembly::mergeRecord(struct CaptureConfig* config)
    {
        char strbuf[maxbuf];
        uint32_t pos, valid_rcd = 0;
        uint8_t buf[65550];

        struct dirent **filelist;
        int numOfFile;

        bool peer;
        bool sni_chk;
        char sni[256], cIP[16], sIP[16];
        uint32_t spt, ext_bound, sni_len;

        std::map<uint32_t, Stream>::iterator mit;

        FILE* fw = fopen(config->outputFileTo.c_str(), "w");
        if (fw == NULL)
            EXIT_WITH_RUNERROR("###ERROR : Could not open ouput csv file");

        for(mit = streams.begin(); mit != streams.end(); mit++)
        {
            if(ab_shouldStop) stop_signal_callback_handler(SIGINT);

            uint32_t ss_idx = mit->first;
            struct Stream* ss = &(mit->second);

            struct timeval ref_tv;
            gettimeofday(&ref_tv, NULL);

            if (ss_idx == 0 || ss_idx + 1 == ab_StreamCount || time_diff(&ref_tv, &(print_tv)) >= 31250)
            {
                print_progressA(ss_idx + 1, ab_StreamCount);
                time_update(&(print_tv), &ref_tv);
            }

            struct Host* fwd = &(ss->client);
            struct Host* rev = &(ss->server);

            sprintf(cIP, "%d.%d.%d.%d", (fwd->IP >> 24) & 0xFF, (fwd->IP >> 16) & 0xFF, (fwd->IP >>  8) & 0xFF, (fwd->IP) & 0xFF);
            sprintf(sIP, "%d.%d.%d.%d", (rev->IP >> 24) & 0xFF, (rev->IP >> 16) & 0xFF, (rev->IP >>  8) & 0xFF, (rev->IP) & 0xFF);

            sni_chk = false;

            numOfFile = scandir((saveDir + std::to_string(ss_idx)+"/").c_str(), &filelist, 0, alphasort);
            
            if (numOfFile < 0) continue;
            for (int i = 0; i < numOfFile; i++)
            {
                // It includes '.' or out-of-order segment files
                if(strlen(filelist[i]->d_name) != 21) continue;

                peer = (filelist[i]->d_name[20] == 'C');

                sprintf(nameBUF, "%s%u/%s", saveDir.c_str(), ss_idx, filelist[i]->d_name);
                FILE* fr = fopen(nameBUF, "r");

                if (fr == NULL)
                    EXIT_WITH_RUNERROR("###ERROR : encounter an error while reading record file");

                while (fgets(strbuf, maxbuf, fr) != NULL)
                {
                    pos = 0;

                    for (const char* tok = strtok(strbuf, ","); tok && *tok; tok = strtok(NULL, ",\n"))
                    {
                        buf[pos++] = (uint8_t)strtol(tok, NULL, 16);
                    }

                    if (pos < 5 || pos < 256*buf[3]+buf[4]+5u) continue;

                    // parsing server name indication (SNI)
                    if(!sni_chk)
                    {
                        sni_chk = true;
                        sni[0] = '\0';
                        // Only Client Hello has 'SNI'
                        if((uint32_t)buf[0] != 22 || (uint32_t)buf[5] != 1) goto writesni;
                        spt = 43;
                        if (pos <= spt) goto writesni;
                        // session_id_length
                        spt += (uint32_t)buf[spt] + 1;		
                        if (pos <= spt+1) goto writesni;
                        // cipher_suite_length
                        spt += 256*(uint32_t)buf[spt] + (uint32_t)buf[spt+1]+2;
                        if (pos <= spt) goto writesni;
                        // compressed_method_length
                        spt += (uint32_t)buf[spt] + 1;
                        if (pos <= spt+1) goto writesni;
                        ext_bound = spt + 256*(uint32_t)buf[spt] + (uint32_t)buf[spt+1] + 1;
                        spt += 2;
                        // extension parsing
                        for(; spt + 4 <= ext_bound; )
                        {
                            // extension type 0 : server name indication 
                            if(256*(uint32_t)buf[spt] + (uint32_t)buf[spt+1] == 0)
                            {
                                if (ext_bound <= spt + 8) break;
                                sni_len = 256*(uint32_t)buf[spt+7] + (uint32_t)buf[spt+8];
                                for(uint32_t j = 0; j < sni_len; j++)
                                {
                                    sni[j] = buf[spt+9+j];
                                }
                                sni[sni_len] = '\0';
                                break;
                            }
                            spt += 256*(uint32_t)buf[spt+2] + (uint32_t)buf[spt+3]+4;
                        }

                        writesni:

                        valid_rcd++;
                        fprintf(fw, "%s:%d,%s:%d,%s,%.8d,%d\n",
                                cIP, fwd->Port, sIP, rev->Port, (sni[0] == '\0' ? "none" : sni), ss_idx, fwd->rcd_cnt + rev->rcd_cnt);
                    }

                    fprintf(fw, "%c", (peer ? 'C' : 'S'));

                    for(uint32_t j = 0; j < pos; j++){
                        if(config->outputTypeHex) fprintf(fw, ",%.2x", buf[j]);
                        else fprintf(fw, ",%d", buf[j]);
                    }

                    fprintf(fw, "\n");

                }
                fclose(fr);
            }
            free(filelist);
        }
        fclose(fw);
        if(valid_rcd > 0) printf("\n");
        printf("**Total Stream#**=========================================== (%u)", valid_rcd);
        streams.clear();
    }

}