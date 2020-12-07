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

#include "utils.h"
#include "handler.h"
#include "assembly.h"

namespace pump
{
    
    char pktBUF[maxbuf];
    char nameBUF[512];

    timeval curr_tv;

    static void onInterrupted(void* cookie)
    {
        bool* stop = (bool*)cookie;
        *stop = true;
    }

    void stop_signal_callback_handler(int signum) {
        printf("\n**All Stop**================================================\n");
        clearTLSniff();
        exit(signum);
    }

    uint32_t hashStream(pump::Packet* packet)
    {
        struct ScalarBuffer vec[5];

        uint16_t portSrc = 0;
        uint16_t portDst = 0;
        int srcPosition = 0;

        pump::TcpLayer* tcpLayer = packet->getLayer<pump::TcpLayer>();
        portSrc = tcpLayer->getHeader()->sport;
        portDst = tcpLayer->getHeader()->dport;

        if (portDst < portSrc)
        {
            srcPosition = 1;
        }

        vec[0 + srcPosition].buffer = (uint8_t*)&portSrc;
        vec[0 + srcPosition].len = 2;
        vec[1 - srcPosition].buffer = (uint8_t*)&portDst;
        vec[1 - srcPosition].len = 2;

        pump::IPv4Layer* ipv4Layer = packet->getLayer<pump::IPv4Layer>();
        if (portSrc == portDst && ipv4Layer->getHeader()->ip_dst < ipv4Layer->getHeader()->ip_src)
        {
            srcPosition = 1;
        }

        vec[2 + srcPosition].buffer = (uint8_t*)&ipv4Layer->getHeader()->ip_src;
        vec[2 + srcPosition].len = 4;
        vec[3 - srcPosition].buffer = (uint8_t*)&ipv4Layer->getHeader()->ip_dst;
        vec[3 - srcPosition].len = 4;
        vec[4].buffer = &(ipv4Layer->getHeader()->proto);
        vec[4].len = 1;

        return fnv_hash(vec, 5);
    }    

    bool isTcpSyn(pump::Packet* packet)
    {
        if (packet->isTypeOf(PROTO_TCP))
        {
            pump::TcpLayer* tcpLayer = packet->getLayer<pump::TcpLayer>();
            return (tcpLayer->getHeader()->flag_syn == 1) && (tcpLayer->getHeader()->flag_ack == 0);
        }

        return false;
    }

    bool isClient(pump::Packet* packet, Stream* ss)
    {
        if(ss->client.port != ss->server.port)
        {
            return ss->client.port == (uint16_t)ntohs(packet->getLayer<pump::TcpLayer>()->getHeader()->sport);
        }

        return (ss->client.ip == packet->getLayer<IPv4Layer>()->getHeader()->ip_src);
    }

    bool isTLSrecord(uint8_t* data, uint32_t seglen)
    {
        if(seglen < 5) return false;

        uint8_t rcd_type = *(data);
        uint16_t rcd_ver = 256**(data+1) + *(data+2);
        uint16_t rcd_len = 256**(data+3) + *(data+4);
        
        if(rcd_type < 20 || rcd_type > 23)
        {
            return false;
        }

        if(rcd_ver/256 != 3 || rcd_ver%256 > 3)
        {
            return false;
        }

        if(rcd_len == 0 || rcd_len >= MAX_RECORD_LEN)
        {
            return false;
        }

        return true;
    }

    bool isSSLv2record(uint8_t* data, uint32_t seglen)
    {
        if(seglen < 7) return false;

        uint8_t rcd_type = *(data+2);
        uint8_t rcd_ver = *(data);
        uint16_t hd_ver = 256**(data+3) + *(data+4);
        uint16_t cip_len = 256**(data+5) + *(data+6);

        if(rcd_ver != 0x80)
        {
            return false;
        }

        if(rcd_type != 1)
        {
            return false;
        }

        if(hd_ver/256 != 3 || hd_ver%256 > 3)
        {
            return false;
        }

        if(cip_len == 0 || cip_len%3 != 0)
        {
            return false;
        }

        return true;
    }

    Assembly::Assembly(timeval tv)
    {
        ab_init_tv = tv;
        ab_base_tv = {0, 0};
        ab_print_tv = {0, 0};
        ab_flowtable = {};
        ab_initiated = {};
        ab_smap = {};
        ab_pkt_cnt = 0;
        ab_flow_cnt = 0;
        ab_rcd_cnt = 0;
        ab_totalbytes = 0;
        registerEvent();
    }

    Assembly::~Assembly() 
	{
        ab_flowtable.clear();
        ab_initiated.clear();
        ab_smap.clear();
	}

    void Assembly::registerEvent()
    {
        ab_stop = false;
        pump::EventHandler::getInstance().onInterrupted(onInterrupted, &ab_stop);
    }

    int Assembly::addNewStream(pump::Packet* packet)
    {
        Flow client, server;

        client.ip = packet->getLayer<IPv4Layer>()->getHeader()->ip_src;
        server.ip = packet->getLayer<IPv4Layer>()->getHeader()->ip_dst;

        client.port = (uint16_t)ntohs(packet->getLayer<pump::TcpLayer>()->getHeader()->sport);
        server.port = (uint16_t)ntohs(packet->getLayer<pump::TcpLayer>()->getHeader()->dport);

        ab_smap[ab_flow_cnt] = {.client = client,
                                .server = server};

        std::string sd = saveDir + std::to_string(ab_flow_cnt) + "/";

        if(access(sd.c_str(), 0) == -1)
            mkdir(sd.c_str(), 0777);

        return ab_flow_cnt++;
    }

    int Assembly::getStreamNumber(pump::Packet* packet)
    {

        uint32_t hash = hashStream(packet);

        bool isSyn = isTcpSyn(packet);

        if (ab_flowtable.find(hash) == ab_flowtable.end())
        {
            // We do not care about truncated flow
            if(!isSyn) return -1;

            ab_flowtable[hash] = addNewStream(packet);
            ab_initiated[hash] = true;
        }
        else
        {
            if (isSyn && ab_initiated[hash] == false)
            {
                ab_flowtable[hash] = addNewStream(packet);
            }
            ab_initiated[hash] = isSyn;
        }
        return ab_flowtable[hash];
    }

    void Assembly::writeTLSrecord(const char* dir, int idx, bool peer)
    {
        sprintf(nameBUF, "%s%u/%c", dir, idx, (peer ? 'C' : 'S'));
        FILE* fp = fopen(nameBUF, "a");

        if (fp == NULL)
            EXIT_WITH_RUNERROR("###ERROR : an error occurs while writting record data %s : %d", nameBUF, ab_pkt_cnt);

        fprintf(fp, "%s", pktBUF);
        fclose(fp);
    }

    void Assembly::cleanOldPacket(const char* dir, int idx, bool peer, Flow* fwd, CaptureConfig* config)
    {
        SegInfo prev_seq_info;
        std::set<SegInfo>::iterator it = fwd->reserved_seq.begin();
        while(it != fwd->reserved_seq.end())
        {
            // We may find the lost segment between prev & it 
            if(prev_seq_info.seq + prev_seq_info.seglen < it->seq)
            {
                break;
            }
            // previous segment size is larger than expected one (frame overlapping)
            else if(prev_seq_info.seq + prev_seq_info.seglen > it->seq)
            {
                fwd->flags |= F_FRAME_OVERLAP;
                break;
            }
            // 
            prev_seq_info.seq = it->seq;
            prev_seq_info.seglen = it->seglen;
            prev_seq_info.is_newrcd = it->is_newrcd;

            it = fwd->reserved_seq.erase(it);
            if(prev_seq_info.is_newrcd)
            {
                fwd->rcd_pt = {0, 0, {}};
                parseReservedPacket(dir, idx, peer, prev_seq_info.seq, config);
                break;
            }
        }
    }

    void Assembly::parseReservedPacket(const char* dir, int idx, bool peer, uint32_t seq, CaptureConfig* config)
    {
        sprintf(nameBUF, "%s%u/%.10dT%c", dir, idx, seq, (peer ? 'C' : 'S'));
        FILE* fp = fopen(nameBUF, "r");

        if (fp == NULL)
            EXIT_WITH_RUNERROR("###ERROR : encounter an error while loading the misplaced segment from %s : %d", nameBUF, ab_pkt_cnt);

        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        uint8_t* pData = new uint8_t[fsize];
        size_t res = fread(pData, 1, fsize, fp);
        if (res != (size_t)fsize)
            EXIT_WITH_RUNERROR("###ERROR : encounter an error while reading the misplaced segment from %s : %d", nameBUF, ab_pkt_cnt);

        pump::Packet reservedPacket = pump::Packet(pData, fsize, {}, true);

        parsePacket(&reservedPacket, config);
    }

    void Assembly::parsePacket(pump::Packet* packet, CaptureConfig* config)
    {

        if (!packet->isTypeOf(PROTO_TCP)
        || !packet->isTypeOf(PROTO_IPv4)) return;

        int ss_idx = getStreamNumber(packet);

        if(ss_idx == -1) return;

        Stream* ss = &ab_smap[ss_idx];

        bool peer = isClient(packet, ss);

        Flow* fwd = &(peer ? ss->client : ss->server);
        Flow* rev = &(peer ? ss->server : ss->client);

        if(fwd->rcd_cnt + rev->rcd_cnt >= config->maxRcdpf) return;

        uint32_t seq = ntohl(packet->getLayer<pump::TcpLayer>()->getHeader()->rawseq);
        uint32_t ack = ntohl(packet->getLayer<pump::TcpLayer>()->getHeader()->rawack);
        uint16_t win = packet->getLayer<pump::TcpLayer>()->getHeader()->rawwin;

        bool isFIN = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_fin == 1);
        bool isSYN = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_syn == 1);
        bool isRST = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_rst == 1);
        bool isACK = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_ack == 1);

        if (!(fwd->flags & F_BASE_SEQ_SET))
        {
            if (isSYN)
            {
                fwd->baseseq = seq;
                fwd->flags |= isACK ? F_SAW_SYNACK : F_SAW_SYN;
            }
            else
            {
                fwd->baseseq = seq - 1;
            }
            fwd->flags |= F_BASE_SEQ_SET;
        }

        seq -= fwd->baseseq;
        ack -= rev->baseseq;

        size_t seglen = packet->getLayer<pump::TcpLayer>()->getLayerPayloadSize();
        uint8_t* payld = packet->getLayer<pump::TcpLayer>()->getLayerPayload();
        
        if (!(rev->flags & F_BASE_SEQ_SET) && isACK)
        {
            rev->baseseq = ack - 1;
            rev->flags |= F_BASE_SEQ_SET;
        }

       fwd->a_flags = 0;

        // ZERO WINDOW PROBE
        if (seglen == 1
        && seq == fwd->nextseq
        && rev->win == 0)
        {
            fwd->a_flags |= TCP_A_ZERO_WINDOW_PROBE;
            WRITE_LOG("└─#ZERO WINDOW PROBE : %d", ab_pkt_cnt);
            goto retrans_check;
        }

        // LOST SEGMENT
        if (fwd->nextseq
        && seq > fwd->nextseq
        && !isRST)
        {
            SegInfo new_info;
            new_info.seq = seq;
            new_info.seglen = seglen;
            new_info.is_newrcd = isTLSrecord(payld, seglen) || isSSLv2record(payld, seglen);

            // duplicate packet with high SEQ (i.e., retransmission)
            if(fwd->reserved_seq.find(new_info) == fwd->reserved_seq.end())
            {
                return;
            }

            fwd->a_flags |= TCP_A_LOST_PACKET;
            WRITE_LOG("└─#LOST SEGMENT : %d", ab_pkt_cnt);
            
            if(fwd->reserved_seq.size() >= MAX_QUEUE_CAPACITY)
            {
                cleanOldPacket(saveDir.c_str(), ss_idx, peer, fwd, config);
            }

            fwd->reserved_seq.insert(new_info);
            sprintf(nameBUF, "%s%u/%.10dT%c", saveDir.c_str(), ss_idx, seq, (peer ? 'C' : 'S'));
            FILE* fp = fopen(nameBUF, "w");
            
            if (fp == NULL)
                EXIT_WITH_RUNERROR("###ERROR : encounter an error while writing the misplaced segment from %s : %d", nameBUF, ab_pkt_cnt);

            fwrite(packet->getData(), packet->getDataLen(), 1, fp);
            fclose(fp);
            WRITE_LOG("└──WRITE TEMPORAL PAYLOAD DATA to %s : %d", nameBUF, ab_pkt_cnt);
            return;
        }

        // KEEP ALIVE
        if (seglen <= 1
        && !(isFIN || isSYN || isRST)
        && fwd->nextseq - 1 == seq)
        {
            fwd->a_flags |= TCP_A_KEEP_ALIVE;
            WRITE_LOG("└─#KEEP ALIVE : %d", ab_pkt_cnt);
        }

        retrans_check:

        // RETRANSMISSION
        if ((seglen > 0 || isSYN || isFIN)
        && fwd->nextseq
        && seq < fwd->nextseq
        && !(seglen > 1 && fwd->nextseq - 1  == seq))
        {
            fwd->a_flags |= TCP_A_RETRANSMISSION;
            WRITE_LOG("└─#RETRANSMISSION : %d", ab_pkt_cnt);
            return;
        }

        uint32_t nextseq = seq + seglen;

        if(isSYN || isFIN) 
        {
            nextseq+=1;
        }

        if ((nextseq > fwd->nextseq || !fwd->nextseq) 
        && !(fwd->a_flags & TCP_A_ZERO_WINDOW_PROBE))
        {
            fwd->nextseq = nextseq;
        }

        fwd->win = win;
        fwd->lastack = ack;

        // TCP PACKETS WITHOUT RECORD DATA
        if(seglen == 0
	    || isSYN
	    || (fwd->a_flags & (TCP_A_ZERO_WINDOW_PROBE | TCP_A_KEEP_ALIVE))) return;

        RecordPointer* rp = &fwd->rcd_pt;

        if (rp->pos)
        {
            WRITE_LOG("└──Read Record (continued) : %d (%d/%d)", ab_pkt_cnt, rp->pos, rp->len);
        }

        int p = 0;

        for (int i = 0; i < (int)seglen; i++)
        {
            if (rp->pos < 5)
            {
                rp->hd[(rp->pos)++] = *(payld + i);
                continue;
            }
            else if (rp->pos == 5)
            {
                // for SSL 2.0
                if(isSSLv2record(rp->hd, 5))
                {
                    rp->len = 256*(int)(rp->hd[0]%64) + (int)rp->hd[1] - 3;
                }
                // for SSL 3.0 ~ TLS 1.3
                else if(isTLSrecord(rp->hd, 5))
                {
                    if (!(peer && fwd->rcd_cnt == 0 && (*(payld + i) != 1 || rp->hd[0] != 22)))
                    {
                        fwd->flags |= F_LOST_HELLO;
                    }
                    else if(!(!peer && fwd->rcd_cnt == 0 && (*(payld + i) != 2 || rp->hd[0] != 22)))
                    {
                        fwd->flags |= F_LOST_HELLO;
                    }
                    rp->len = 256*(int)rp->hd[3] + (int)rp->hd[4];
                }
                else
                {
                    rp->pos = 0;
                    fwd->a_flags |= TCP_A_NON_RECORD;
                    break;
                }
                if(!(config->quitemode))
                {
                    char cIP[16], sIP[16];

                    parseIPV4(cIP, ss->client.ip);
                    parseIPV4(sIP, ss->server.ip);

                    printf("[Client] %s:%d  ", cIP, ss->client.port);
                    for (int j = strlen(cIP); j < 15; j++) printf(" ");
                    uint16_t temp = ss->client.port;
                    for (; temp < 10000; temp *= 10) printf(" ");
                    if(!peer) printf("<"); 
                    uint16_t typelen = (recordType.at(rp->hd[0])).length() 
                        + (rp->hd[0] != 22 ? 0 : (handshakeType.find(*(payld + i)) == handshakeType.end() ? 11 : (handshakeType.at(*(payld + i))).length()));
                    for (int j = 0; j < (50-typelen)/2 + (!peer ? 0 : 1); j++) printf("-");
                    printf(" %s%s ", (recordType.at(rp->hd[0])).c_str(),
                        (rp->hd[0] != 22 ? "" : (handshakeType.find(*(payld + i)) == handshakeType.end() ? "(encrypted)" : (handshakeType.at(*(payld + i))).c_str())));
                    for (int j = 0; j < (50-typelen+1)/2 + (!peer ? 0 : -1); j++) printf("-");
                    if(peer) printf(">"); 
                    for (int j = strlen(sIP); j < 15; j++) printf(" ");
                    temp = ss->server.port;
                    for (; temp < 10000; temp *= 10) printf(" ");
                    printf("%s:%d [Server]\n", sIP, ss->server.port);
                }
                if(config->outputFileTo != "")
                {
                    fwd->rcd_idx++;
                    sprintf(pktBUF+p, "%.5d,%.2x,%.2x,%.2x,%.2x,%.2x", 
                        fwd->rcd_idx + rev->rcd_idx, rp->hd[0], rp->hd[1], rp->hd[2], rp->hd[3], rp->hd[4]);
                    p += 20;
                }
            }
            if(config->outputFileTo != "")
            {
                sprintf(pktBUF+p, ",%.2x", *(payld + i));
                p += 3;
            }
            if(++(rp->pos) == rp->len + 5u)
            {
                rp->pos = 0;
                fwd->rcd_cnt++;
                ab_rcd_cnt++;
                if(config->outputFileTo != "")
                {
                    sprintf(pktBUF+(p++), "\n");
                    pktBUF[p] = '\0';
                    writeTLSrecord(saveDir.c_str(), ss_idx, peer);
                    p = 0;
                }
                WRITE_LOG("└──Read Record : %d (%d)", ab_pkt_cnt, rp->len);
                if(ab_rcd_cnt == config->maxRcd)
                {
                    raise(SIGINT);
                    return;
                }
                if(fwd->rcd_cnt + rev->rcd_cnt >= config->maxRcdpf) return;
            }
        }

        // Write the front part of a record
        if(rp->pos > 0)
        {
            if(config->outputFileTo != "")
            {
                pktBUF[p] = '\0';
                writeTLSrecord(saveDir.c_str(), ss_idx, peer);
            }
            WRITE_LOG("└──Read Record : %d, but it continues on next packet (%d/%d)", ab_pkt_cnt, rp->pos, rp->len);      
        }

        if(fwd->reserved_seq.empty()) return;

        auto seg_info = fwd->reserved_seq.begin();

        // If the next expected seq num is equal to the first element in queue, there would be an out-of-order issue
        if(seg_info->seq == nextseq)
        {
            fwd->reserved_seq.erase(seg_info);
            parseReservedPacket(saveDir.c_str(), ss_idx, peer, nextseq, config);
        }
    }

    void Assembly::managePacket(pump::Packet* packet, CaptureConfig* config)
    {
        timeval ref_tv = packet->getTimeStamp();
        uint32_t pk_len = packet->getDataLen();
        if(ab_pkt_cnt == 0) time_update(&ab_base_tv, &ref_tv);
        int64_t delta_time = time_diff(&ref_tv, &ab_base_tv);

        gettimeofday(&curr_tv, NULL);

        if (ab_pkt_cnt >= config->maxPacket 
        || time_diff(&ref_tv, &ab_base_tv)/1000000 >= (int64_t)config->maxTime)
        {
            raise(SIGINT);
            return;
        }

        ab_totalbytes += pk_len;
        ab_pkt_cnt++;

        if (delta_time == 0 || time_diff(&ref_tv, &ab_print_tv) >= 31250)
        {
            struct rusage r_usage;
            getrusage(RUSAGE_SELF, &r_usage);
            if(r_usage.ru_maxrss > MEMORY_LIMIT)
                EXIT_WITH_RUNERROR("###ERROR : The process consume too much memory");

            if(config->quitemode) print_progressM(ab_pkt_cnt);
            time_update(&ab_print_tv, &ref_tv);
        }

        parsePacket(packet, config);
    }

    void Assembly::mergeRecord(CaptureConfig* config)
    {
        char strbuf[maxbuf];
        uint32_t valid_rcd = 0;
        uint8_t bufc[maxbuf], bufs[maxbuf];

        bool sni_chk;
        char sni[256], cIP[16], sIP[16];
        uint16_t spt, ext_bound, sni_len, eofc, eofs, pc, ps, rc, rs;

        std::map<uint32_t, Stream>::iterator it;

        FILE* fw = fopen(config->outputFileTo.c_str(), "w");
        if (fw == NULL)
            EXIT_WITH_RUNERROR("###ERROR : Could not open ouput csv file");

        for(it = ab_smap.begin(); it != ab_smap.end(); it++)
        {
            if(ab_stop) stop_signal_callback_handler(SIGINT);

            uint32_t ss_idx = it->first;
            Stream* ss = &it->second;

            timeval ref_tv;
            gettimeofday(&ref_tv, NULL);

            if (ss_idx == 0 
            || ss_idx + 1 == ab_flow_cnt 
            || time_diff(&ref_tv, &ab_print_tv) >= 31250)
            {
                print_progressA(ss_idx + 1, ab_flow_cnt);
                time_update(&ab_print_tv, &ref_tv);
            }

            Flow* fwd = &ss->client;
            Flow* rev = &ss->server;

            parseIPV4(cIP, fwd->ip);
            parseIPV4(sIP, rev->ip);

            while(!fwd->reserved_seq.empty())
            {
                cleanOldPacket(saveDir.c_str(), ss_idx, true, fwd, config);
            }

            while(!rev->reserved_seq.empty())
            {
                cleanOldPacket(saveDir.c_str(), ss_idx, false, rev, config);
            }

            sni_chk = false;

            eofc = fwd->rcd_cnt;
            eofs = rev->rcd_cnt;

            if(eofc + eofs > 0)
            {
                FILE* fc;
                FILE* fs;

                fc = fopen((saveDir + std::to_string(ss_idx) + "/C").c_str(), "r");
                fs = fopen((saveDir + std::to_string(ss_idx) + "/S").c_str(), "r");

                if(fc == NULL && fs == NULL)
                {
                    goto closemerge;
                }           

                pc = ps = rc = rs = 0;
                while(eofc > 0 || eofs > 0 || pc > 0 || ps > 0)
                {
                    if(eofc > 0 && pc == 0 && fgets(strbuf, maxbuf, fc) != NULL)
                    {
                        eofc--;

                        const char* tok = strtok(strbuf, ",");
                        rc = (uint32_t)atoi(tok);

                        for (tok = strtok(NULL, ",\n"); tok && *tok; tok = strtok(NULL, ",\n"))
                        {
                            bufc[pc++] = (uint8_t)strtol(tok, NULL, 16);
                        }
                    }

                    if(eofs > 0 && ps == 0 && fgets(strbuf, maxbuf, fs) != NULL)
                    {
                        eofs--;

                        const char* tok = strtok(strbuf, ",");
                        rs = (uint32_t)atoi(tok);

                        for (tok = strtok(NULL, ",\n"); tok && *tok; tok = strtok(NULL, ",\n"))
                        {
                            bufs[ps++] = (uint8_t)strtol(tok, NULL, 16);
                        }
                    }

                    if(ps > 0 && (pc == 0 || rc > rs))
                    {
                        // SSL session should begin with client-side message
                        if(!sni_chk) break;

                        fprintf(fw, "S");

                        for(uint32_t i = 0; i < ps; i++){
                            if(config->outputTypeHex) fprintf(fw, ",%.2x", bufs[i]);
                            else fprintf(fw, ",%d", bufs[i]);
                        }
                        ps = 0;
                        fprintf(fw, "\n");
                    }
                    else if(pc > 0 && (ps == 0 || rc < rs))
                    {
                        // parsing server name indication
                        if(!sni_chk)
                        {
                            sni_chk = true;
                            sni[0] = '\0';
                            // Only Client Hello has 'SNI'
                            if((uint32_t)bufc[0] != 22 || (uint32_t)bufc[5] != 1) goto writesni;
                            spt = 43;
                            if (pc <= spt) goto writesni;
                            // session_id_length
                            spt += (uint32_t)bufc[spt] + 1;		
                            if (pc <= spt+1) goto writesni;
                            // cipher_suite_length
                            spt += 256*(uint32_t)bufc[spt] + (uint32_t)bufc[spt+1]+2;
                            if (pc <= spt) goto writesni;
                            // compressed_method_length
                            spt += (uint32_t)bufc[spt] + 1;
                            if (pc <= spt+1) goto writesni;
                            ext_bound = spt + 256*(uint32_t)bufc[spt] + (uint32_t)bufc[spt+1] + 1;
                            spt += 2;
                            // extension parsing
                            for(; spt + 4 <= ext_bound; )
                            {
                                // extension type 0 : server name indication 
                                if(256*(uint32_t)bufc[spt] + (uint32_t)bufc[spt+1] == 0)
                                {
                                    if (ext_bound <= spt + 8) break;
                                    sni_len = 256*(uint32_t)bufc[spt+7] + (uint32_t)bufc[spt+8];
                                    for(uint32_t i = 0; i < sni_len; i++)
                                    {
                                        sni[i] = bufc[spt+9+i];
                                    }
                                    sni[sni_len] = '\0';
                                    break;
                                }
                                spt += 256*(uint32_t)bufc[spt+2] + (uint32_t)bufc[spt+3]+4;
                            }                    

                            writesni:

                            fprintf(fw, "%s:%d,%s:%d,%s,%.8d,%d\n",
                                cIP, fwd->port, sIP, rev->port, (sni[0] == '\0' ? "none" : sni), ss_idx, fwd->rcd_cnt + rev->rcd_cnt);
                            valid_rcd++;
                        }

                        fprintf(fw, "C");

                        for(uint32_t i = 0; i < pc; i++){
                            if(config->outputTypeHex) fprintf(fw, ",%.2x", bufc[i]);
                            else fprintf(fw, ",%d", bufc[i]);
                        }
                        pc = 0;
                        fprintf(fw, "\n");
                    }
                }
                closemerge:

                if(fc != NULL) fclose(fc);
                if(fs != NULL) fclose(fs);
            }
        }
        fclose(fw);
        printf("\n");
        printf("**Total SSL flow#**========================================= (%u)", valid_rcd);
    }

    void Assembly::close()
    {
        ab_smap.clear();
        ab_initiated.clear();
        ab_flowtable.clear();
    }

}