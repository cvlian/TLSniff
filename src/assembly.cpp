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
    /* Buffer to temporarily store the payload data */
    char pktBUF[maxbuf];
    /* Buffer to temporarily store the file name */
    char nameBUF[512];

    /* Catch a signal (i.e., SIGINT) */
    static void onInterrupted(void* cookie)
    {
        bool* stop = (bool*)cookie;
        *stop = true;
    }

    /* Make a clean exit on interrupts */
    void stop_signal_callback_handler(int signum) {
        printf("\n**All Stop**================================================\n");
        clearTLSniff();
        exit(signum);
    }

    /*
     * Compute a hash value for a given packet
     * Packets with the same pair of source/destination IP addresses and port numbers (4-tuples)
     * will belong to the same connection
     */
    uint32_t hashStream(pump::Packet* packet)
    {
        struct ScalarBuffer vec[4];

        uint16_t sport = 0;
        uint16_t dport = 0;
        int srcPosition = 0;

        pump::TcpLayer* tcpLayer = packet->getLayer<pump::TcpLayer>();
        sport = tcpLayer->getHeader()->sport;
        dport = tcpLayer->getHeader()->dport;

        if (dport < sport)
        {
            srcPosition = 1;
        }

        vec[0 + srcPosition].buffer = (uint8_t*)&sport;
        vec[0 + srcPosition].len = 2;
        vec[1 - srcPosition].buffer = (uint8_t*)&dport;
        vec[1 - srcPosition].len = 2;

        pump::IPv4Layer* ipv4Layer = packet->getLayer<pump::IPv4Layer>();
        if (sport == dport && ipv4Layer->getHeader()->ip_dst < ipv4Layer->getHeader()->ip_src)
        {
            srcPosition = 1;
        }

        vec[2 + srcPosition].buffer = (uint8_t*)&ipv4Layer->getHeader()->ip_src;
        vec[2 + srcPosition].len = 4;
        vec[3 - srcPosition].buffer = (uint8_t*)&ipv4Layer->getHeader()->ip_dst;
        vec[3 - srcPosition].len = 4;

        return fnv_hash(vec, 4);
    }    

    /* Check whether SYN and ACK flag is 1 and 0, respectively */
    bool isTcpSyn(pump::Packet* packet)
    {
        if (packet->isTypeOf(PROTO_TCP))
        {
            pump::TcpLayer* tcpLayer = packet->getLayer<pump::TcpLayer>();
            bool isSYN = (tcpLayer->getHeader()->flag_syn == 1);
            bool isACK = (tcpLayer->getHeader()->flag_ack == 1);
            return isSYN && !isACK;
        }

        return false;
    }

    /* Check whether the packet transmitted by a host who initiates the session */
    bool isClient(pump::Packet* packet, Stream* ss)
    {
        if(ss->client.port != ss->server.port)
        {
            uint16_t port = ntohs(packet->getLayer<pump::TcpLayer>()->getHeader()->sport);
            return ss->client.port == port;
        }

        uint32_t ip = packet->getLayer<IPv4Layer>()->getHeader()->ip_src;
        return ss->client.ip == ip;
    }

    /* Detect the TLS record header (SSLv3, TLS 1.0 ~ 1.3) in a heuristic way
     * 
     * byte 0    : record message type (must be in range of 0x14 to 0x17)
     * byte 1-2  : record version (must be in range of 0x300 to 0x303)
     * byte 3-4  : record length exclusive of header (cannot be 0, must be less than 0x4800)
     */
    bool isTLSrecord(uint8_t* data, uint32_t seglen)
    {
        if(seglen < 5) return false;

        uint8_t rcd_type = *(data);
        uint16_t rcd_ver = 256**(data+1) + *(data+2);
        uint16_t rcd_len = 256**(data+3) + *(data+4);
        
        if(rcd_type < 0x14 || rcd_type > 0x17)
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

    /* Detect the obsolete TLS record header (SSLv2) in a heuristic way
     * 
     * byte 0    : record version (must be 0x80)
     * byte 2    : record message type (0x1, namely client hello)
     * byte 3-4  : record handshake version (must be in range of 0x300 to 0x303)
     * byte 5-6  : cipher spec length (cannot be 0, must be multiple of 3)
     */
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

    /* True if the record has plaintext TLS handshake data */
    bool isUnencryptedHS(uint8_t curr_rcd_type, uint8_t prev_rcd_type)
    {
        return curr_rcd_type == 0x16 && prev_rcd_type != 0x14;
    }

    Assembly::Assembly(timeval tv)
    {
        ab_init_tv = tv;
        ab_print_tv = {0, 0};
        ab_flowtable = {};
        ab_initiated = {};
        ab_smap = {};
        ab_pkt_cnt = 0;
        ab_flow_cnt = 0;
        ab_rcd_cnt = 0;
        ab_totalbytes = 0;

        // Set handler for Ctrl+C key
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

        client.port = ntohs(packet->getLayer<pump::TcpLayer>()->getHeader()->sport);
        server.port = ntohs(packet->getLayer<pump::TcpLayer>()->getHeader()->dport);

        // allocate a structure to hold bidirectional information of the new TCP stream 
        ab_smap[ab_flow_cnt] = {.client = client,
                                .server = server};

        std::string sd = saveDir + std::to_string(ab_flow_cnt) + "/";

        // Create a directory to put temporal record data in
        if(access(sd.c_str(), 0) == -1)
            mkdir(sd.c_str(), 0777);

        return ab_flow_cnt++;
    }

    int Assembly::getStreamNumber(pump::Packet* packet)
    {
        // TLS is positioned over the TCP/IP in the protocol stack
        // We will ignore other protocol families for the efficiency
        if (!packet->isTypeOf(PROTO_TCP)
        || !packet->isTypeOf(PROTO_IPv4)) return -1;

        uint32_t hash = hashStream(packet);

        bool isSyn = isTcpSyn(packet);

        // We haven't seen a packet with this converstation yet, so create one
        if (ab_flowtable.find(hash) == ab_flowtable.end())
        {
            // We do not care about truncated flow
            // Conversation must begin with 3-way TCP handshaking as we can keep track of
            // exactly how many records are captured, or where a message starts and stops
            if(!isSyn) return -1;

            // Add it to the list of conversations
            ab_flowtable[hash] = addNewStream(packet);
            ab_initiated[hash] = true;
        }
        // Look up the conversation
        else
        {
            // If we encounter an SYN packet with a hash value already stored in the flow table,
            // this indicate a new session, so the flow table assigns a new stream
            // index to such conversation unless the we had seen SYN as last packet,
            // which is an indication of SYN retransmission
            if (isSyn && ab_initiated[hash] == false)
            {
                ab_flowtable[hash] = addNewStream(packet);
            }

            ab_initiated[hash] = isSyn;
        }

        return ab_flowtable[hash];
    }

    void Assembly::writeTLSrecord(int idx, bool peer)
    {
        // Write the record data to a file specified by a given path
        sprintf(nameBUF, "%s%u/%c", saveDir.c_str(), idx, (peer ? 'C' : 'S'));
        FILE* fp = fopen(nameBUF, "a");

        if (fp == NULL)
            EXIT_WITH_RUNERROR("###ERROR : failure of writting record data : %d", ab_pkt_cnt);

        fprintf(fp, "%s", pktBUF);
        fclose(fp);
    }

    void Assembly::displayTLSrecord(Stream* ss, bool peer, uint8_t rcd_type, uint8_t hs_type)
    {
        char cIP[16], sIP[16];
        std::string type;
        uint16_t typelen;

        parseIPV4(cIP, ss->client.ip);
        parseIPV4(sIP, ss->server.ip);

        type = recordType.at(rcd_type).first;
        typelen = recordType.at(rcd_type).second;

        if(rcd_type == 22)
        {
            if(handshakeType.find(hs_type) == handshakeType.end())
            {
                type += "(encrypted)";
                typelen += 11;
            }
            else
            {
                type += handshakeType.at(hs_type).first;
                typelen += handshakeType.at(hs_type).second;
            }
        }  

        // Record exchange will be displayed as follow:
        // [Clinet] ip:port <---Record Type---> ip:port [Server]
        printf("[Client] %s:%d  ", cIP, ss->client.port);
        for (int j = strlen(cIP); j < 15; j++) printf(" ");
        uint16_t temp = ss->client.port;
        for (; temp < 10000; temp *= 10) printf(" ");
        
        if(!peer) printf("<"); 
        for (int j = 0; j < (50-typelen)/2 + (!peer ? 0 : 1); j++) printf("-");
        printf(" %s ", type.c_str());
        for (int j = 0; j < (50-typelen+1)/2 + (!peer ? 0 : -1); j++) printf("-");
        if(peer) printf(">");

        for (int j = strlen(sIP); j < 15; j++) printf(" ");
        temp = ss->server.port;
        for (; temp < 10000; temp *= 10) printf(" ");
        printf("%s:%d [Server]\n", sIP, ss->server.port);
    }

    void Assembly::cleanOldPacket(int idx, bool peer, Flow* fwd, CaptureConfig* config)
    {
        SegInfo prev_seq_info;
        std::set<SegInfo>::iterator it = fwd->reserved_seq.begin();

        // To avoid out of memory issue due to packets whose parsining order is delayed,
        // We have to frequently Remove or packets from the packetQueue until it becomes empty
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

            prev_seq_info.seq = it->seq;
            prev_seq_info.seglen = it->seglen;
            prev_seq_info.is_newrcd = it->is_newrcd;

            it = fwd->reserved_seq.erase(it);

            // If the stored payload begins with a new record header, then parse it
            if(prev_seq_info.is_newrcd)
            {
                // Initialize a data structure for memorizing the record boundary 
                fwd->rcd_pt = {0, 0, 0, 0, 0, {}};
                parseReservedPacket(idx, peer, prev_seq_info.seq, config);
                break;
            }
        }
    }

    void Assembly::parseReservedPacket(int idx, bool peer, uint32_t seq, CaptureConfig* config)
    {
        // Read the unparsed record data from a file specified by a given path
        sprintf(nameBUF, "%s%u/%.10dT%c", saveDir.c_str(), idx, seq, (peer ? 'C' : 'S'));
        FILE* fp = fopen(nameBUF, "r");

        if (fp == NULL)
            EXIT_WITH_RUNERROR("###ERROR : failure of reading record data : %d", ab_pkt_cnt);

        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        uint8_t* pData = new uint8_t[fsize];
        size_t res = fread(pData, 1, fsize, fp);

        if (res != (size_t)fsize)
            EXIT_WITH_RUNERROR("###ERROR : ailure of reading record data : %d", ab_pkt_cnt);

        pump::Packet reservedPacket = pump::Packet(pData, fsize, {}, true);

        parsePacket(&reservedPacket, config);
    }

    void Assembly::parsePacket(pump::Packet* packet, CaptureConfig* config)
    {
        int ss_idx = getStreamNumber(packet);

        // Non TCP/IP packet or a packet in a truncated flow
        if(ss_idx == -1) return;

        Stream* ss = &ab_smap[ss_idx];

        bool peer = isClient(packet, ss);

        // Get the data structures containing flow-level information in
        // the same/reverse direction as the current packet
        Flow* fwd = &(peer ? ss->client : ss->server);
        Flow* rev = &(peer ? ss->server : ss->client);

        if(fwd->rcd_cnt + rev->rcd_cnt >= config->maxRcdpf) return;

        uint32_t seq = ntohl(packet->getLayer<pump::TcpLayer>()->getHeader()->rawseq);
        uint32_t ack = ntohl(packet->getLayer<pump::TcpLayer>()->getHeader()->rawack);
        uint16_t win = packet->getLayer<pump::TcpLayer>()->getHeader()->rawwin;

        bool isFIN = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_fin == 1);
        bool isSYN = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_syn == 1);
        bool isRST = (packet->getLayer<pump::TcpLayer>()->getHeader()->flag_rst == 1);

        // If this is the first packet for this direction,
        // we need to store the base sequence number
        // This enables us to calculate the relative seq/ack numbers,
        // which is helpful for the advanced analysis of the given segment 
        if (!(fwd->flags & F_BASE_SEQ_SET))
        {
            fwd->baseseq = seq;
            fwd->flags |= F_BASE_SEQ_SET;
        }

        // Compute the relative seq/ack numbers
        seq -= fwd->baseseq;
        ack -= rev->baseseq;

        size_t seglen = packet->getLayer<pump::TcpLayer>()->getLayerPayloadSize();
        uint8_t* payld = packet->getLayer<pump::TcpLayer>()->getLayerPayload();

        fwd->a_flags = 0;

        // Set 'ZERO WINDOW PROBE' when
        // (1) segment size is one 
        // (2) sequence number is equal to the next expected sequence number
        // (3) last seen window size in the reverse direction was zero 
        if (seglen == 1
        && seq == fwd->nextseq
        && rev->win == 0)
        {
            fwd->a_flags |= TCP_A_ZERO_WINDOW_PROBE;
            //WRITE_LOG("└─#ZERO WINDOW PROBE : %d", ab_pkt_cnt);
            goto retrans_check;
        }

        // Set 'LOST SEGMENT' when
        // (1) current sequence number is greater than the next expected sequence number
        // (2) RST is not set
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
            //WRITE_LOG("└─#LOST SEGMENT : %d", ab_pkt_cnt);
            
            // Clear some old payload data
            // They are unlikely to be used over time as some of the lost segments may
            // have a certain portion of trimmed record payload
            if(fwd->reserved_seq.size() >= MAX_QUEUE_CAPACITY)
            {
                cleanOldPacket(ss_idx, peer, fwd, config);
            }

            // Store this until the lost packets arrive later
            fwd->reserved_seq.insert(new_info);
            sprintf(nameBUF, "%s%u/%.10dT%c", saveDir.c_str(), ss_idx, seq, (peer ? 'C' : 'S'));
            FILE* fp = fopen(nameBUF, "w");
            
            if (fp == NULL)
                EXIT_WITH_RUNERROR("###ERROR : failure of writting record data : %d", ab_pkt_cnt);

            fwrite(packet->getData(), packet->getDataLen(), 1, fp);
            fclose(fp);
            //WRITE_LOG("└──WRITE TEMPORAL PAYLOAD DATA to %s : %d", nameBUF, ab_pkt_cnt);
            return;
        }

        // Set 'KEEP ALIVE' when
        // (1) segment size is zero or one 
        // (2) sequence number is one byte less than the next expected sequence number
        // (3) any of SYN, FIN, or RST are set
        if (seglen <= 1
        && !(isFIN || isSYN || isRST)
        && fwd->nextseq - 1 == seq)
        {
            fwd->a_flags |= TCP_A_KEEP_ALIVE;
            //WRITE_LOG("└─#KEEP ALIVE : %d", ab_pkt_cnt);
        }

        retrans_check:

        // Set 'RETRANSMISSION' when
        // (1) not a KEEP-ALIVE 
        // (2) seqgment length is greater than zero or the SYN or FIN is set
        // (3) next expected sequence number is greater than the current sequence number
        if ((seglen > 0 || isSYN || isFIN)
        && fwd->nextseq
        && seq < fwd->nextseq)
        {
            // Ignore this, since we parsed packets in ascending order of their sequence number,
            // which means the retransmission of dupicated data while its original copy already
            // arrived and handled properly
            fwd->a_flags |= TCP_A_RETRANSMISSION;
            //WRITE_LOG("└─#RETRANSMISSION : %d", ab_pkt_cnt);
            return;
        }

        // next sequence number is seglen bytes away, plus SYN/FIN which counts as one byte
        uint32_t nextseq = seq + seglen;

        if(isSYN || isFIN) 
        {
            nextseq+=1;
        }

        // Store the highest number seen so far for nextseq so we can detect
        // when we receive segments that arrive with a "hole"
        // If we don't have anything since before, just store what we got
        // ZEROWINDOWPROBEs are special and don't really advance the next sequence number
        if ((nextseq > fwd->nextseq || !fwd->nextseq) 
        && !(fwd->a_flags & TCP_A_ZERO_WINDOW_PROBE))
        {
            fwd->nextseq = nextseq;
        }

        fwd->win = win;
        fwd->lastack = ack;

        // TCP packets without record data
        if(seglen == 0
	    || isSYN
	    || (fwd->a_flags & (TCP_A_ZERO_WINDOW_PROBE | TCP_A_KEEP_ALIVE))) return;

        RecordPointer* rp = &fwd->rcd_pt;

        if (rp->rcd_pos)
        {
            WRITE_LOG("└──Read Record (continued) : %d", ab_pkt_cnt);
        }

        int p = 0;

        for (int i = 0; i < (int)seglen; i++)
        {
            // Store the first 5 bytes to verify this has a record frame 
            if (rp->rcd_pos < 5)
            {
                rp->hd[(rp->rcd_pos)++] = *(payld + i);
                continue;
            }
            else if (rp->rcd_pos == 5)
            {
                // for SSL 2.0
                if(isSSLv2record(rp->hd, 5))
                {
                    // In SSLv2, record length is specified in the 1-2 bytes 
                    rp->rcd_len = 256*(int)(rp->hd[0]%64) + (int)rp->hd[1] - 3;
                }
                // for SSL 3.0 ~ TLS 1.3
                else if(isTLSrecord(rp->hd, 5))
                {
                    // Check whether the client node sends 'Client Hello' as its first message
                    if (!(peer 
                    && fwd->rcd_cnt == 0 
                    && (*(payld + i) != 1 || rp->hd[0] != 22)))
                    {
                        // Not a complete TLS session
                        fwd->flags |= F_LOST_HELLO;
                    }
                    // Check whether the server node sends 'Server Hello' as its first message
                    else if(!(!peer 
                    && fwd->rcd_cnt == 0 
                    && (*(payld + i) != 2 || rp->hd[0] != 22)))
                    {
                        // Not a complete TLS session
                        fwd->flags |= F_LOST_HELLO;
                    }

                    // In SSLv3 ~ TLS 1.3, record length is specified in the 4-5 bytes 
                    rp->rcd_len = 256*(int)rp->hd[3] + (int)rp->hd[4];
                }
                else
                {
                    // The header is not in a TLS record format
                    rp->rcd_pos = 0;
                    fwd->a_flags |= TCP_A_NON_RECORD;
                    break;
                }

                // Take 'Multiple Handshake Messages' into account
                // Display or write the header field of a record first
                // when it is not a TLS handshake message (exceptional case : Handshake Finished) 
                if(!isUnencryptedHS(rp->hd[0], rp->prev_rcd_type))
                {
                    // Display the record exchange step to stdout
                    if(!(config->quitemode))
                    {
                        displayTLSrecord(ss, peer, rp->hd[0], 255);
                    }

                    // Store the transmission order of current record and its header
                    if(config->outputFileTo != "")
                    {
                        fwd->rcd_idx++;
                        sprintf(pktBUF+p, "%.5d,%.2x,%.2x,%.2x,%.2x,%.2x", 
                            fwd->rcd_idx + rev->rcd_idx,
                            rp->hd[0], rp->hd[1], rp->hd[2], rp->hd[3], rp->hd[4]);
                        p += 20;
                    }
                }
            }

            // If this is an unencrypted handshake, we also dissect the handshake data field
            // since there is a mere possibility that several records share a same record header
            // In such a case, each handshake message directly leads to the next one
            if(isUnencryptedHS(rp->hd[0], rp->prev_rcd_type))
            {
                // Reaches end of the current record
                if(++(rp->rcd_pos) == rp->rcd_len + 5u)
                {
                    rp->rcd_pos = 0;
                }

                // Store the first 4 bytes field of the handshake message
                if(++rp->hs_pos <= 4)
                {
                    rp->hd[4 + rp->hs_pos] = *(payld + i);

                    if(rp->hs_pos == 4)
                    {
                        // Display the record exchange step to stdout
                        if(!(config->quitemode))
                        {
                            displayTLSrecord(ss, peer, rp->hd[0], rp->hd[5]);
                        }

                        // Store the transmission order of current record and its header
                        if(config->outputFileTo != "")
                        {
                            fwd->rcd_idx++;
                            sprintf(pktBUF+p, "%.5d,%.2x,%.2x,%.2x,%.2x,%.2x,%.2x,%.2x,%.2x,%.2x", 
                                fwd->rcd_idx + rev->rcd_idx,
                                rp->hd[0], rp->hd[1], rp->hd[2], rp->hd[3], rp->hd[4],
                                rp->hd[5], rp->hd[6], rp->hd[7], rp->hd[8]);
                            p += 32;
                        }

                        rp->hs_len = 256*rp->hd[7] + rp->hd[8];

                        // Zero length handshake 
                        // Received message is probably a 'server hello done'
                        if(rp->hs_len == 0)
                        {
                            goto saveHS;
                        }
                    }
                    //++rp->rcd_pos;
                    continue;
                }

                // Store each payload octect to a buffer
                if(config->outputFileTo != "")
                {
                    sprintf(pktBUF+p, ",%.2x", *(payld + i));
                    p += 3;
                }

                if(rp->hs_pos < rp->hs_len + 4u) continue;
                
                // Reaches end of the current handshake message
                saveHS:

                rp->hs_pos = 0;
                rp->prev_rcd_type = 0x16;

                WRITE_LOG("└──Read Record : %d (%d)", ab_pkt_cnt, rp->hs_len+4);
                goto saveRCD;
            }
            // Deal with non-handshake message
            else
            {
                // Store each payload octect to a buffer
                if(config->outputFileTo != "")
                {
                    sprintf(pktBUF+p, ",%.2x", *(payld + i));
                    p += 3;
                }

                if(++(rp->rcd_pos) < rp->rcd_len + 5u) continue;
                
                // Reaches end of the current record
                rp->rcd_pos = 0;
                rp->prev_rcd_type = rp->hd[0];

                WRITE_LOG("└──Read Record : %d (%d)", ab_pkt_cnt, rp->rcd_len);
                goto saveRCD;
            }

            continue;

            saveRCD:

            fwd->rcd_cnt++;
            ab_rcd_cnt++;

            if(config->outputFileTo != "")
            {
                sprintf(pktBUF+(p++), "\n");
                pktBUF[p] = '\0';
                writeTLSrecord(ss_idx, peer);
                p = 0;
            }

            // Stop reading if we have the maximum number of records
            if(ab_rcd_cnt == config->maxRcd)
            {
                raise(SIGINT);
                return;
            }

            // Stop capturing packets received in this conversation
            // if we have the maximum number of records per flow
            if(fwd->rcd_cnt + rev->rcd_cnt >= config->maxRcdpf) return;
        }

        // Still read the record payload, but some octets left in subsequent packets,
        // just have to write the front part of a record
        if(rp->rcd_pos > 0)
        {
            if(config->outputFileTo != "")
            {
                pktBUF[p] = '\0';
                writeTLSrecord(ss_idx, peer);
            }

            WRITE_LOG("└──Read Record : %d, continues on next packet", ab_pkt_cnt);      
        }

        // When this has the highest sequence number ever seen,
        // payloadQueue does not have reserved data
        if(fwd->reserved_seq.empty()) return;

        auto seg_info = fwd->reserved_seq.begin();

        // If the next expected seq num is equal to the first element in queue,
        // there would be an out-of-order issue
        if(seg_info->seq == nextseq)
        {
            fwd->reserved_seq.erase(seg_info);
            parseReservedPacket(ss_idx, peer, nextseq, config);
        }
    }

    void Assembly::managePacket(pump::Packet* packet, CaptureConfig* config)
    {
        timeval curr_tv;
        gettimeofday(&curr_tv, NULL);

        uint32_t pk_len = packet->getDataLen();
        int64_t delta_time = time_diff(&curr_tv, &ab_init_tv);

        // Stop reading if we have the maximum number of packets
        // or the capture timer is out
        if (ab_pkt_cnt >= config->maxPacket 
        || delta_time/1000000 >= (int64_t)config->maxTime)
        {
            raise(SIGINT);
            return;
        }

        ab_totalbytes += pk_len;
        ab_pkt_cnt++;

        // Show the capturing progress 
        if (time_diff(&curr_tv, &ab_print_tv) >= 31250)
        {
            struct rusage r_usage;
            getrusage(RUSAGE_SELF, &r_usage);

            // Report an out-of-memory condition and abort
            if(r_usage.ru_maxrss > MEMORY_LIMIT)
                EXIT_WITH_RUNERROR("###ERROR : The process consume too much memory");

            if(config->quitemode) print_progressM(ab_pkt_cnt);
            time_update(&ab_print_tv, &curr_tv);
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

        // Rearrange the records from both client and server sides
        for(it = ab_smap.begin(); it != ab_smap.end(); it++)
        {
            // User wants to stop the processing, close the merge Mod 
            if(ab_stop) stop_signal_callback_handler(SIGINT);

            uint32_t ss_idx = it->first;
            Stream* ss = &it->second;

            timeval ref_tv;
            gettimeofday(&ref_tv, NULL);

            // Show the merging progress 
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

            // Complete parsing process for the remaining payload data
            while(!fwd->reserved_seq.empty())
            {
                cleanOldPacket(ss_idx, true, fwd, config);
            }

            while(!rev->reserved_seq.empty())
            {
                cleanOldPacket(ss_idx, false, rev, config);
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
                    // Read the client's record message
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

                    // Read the server's record message
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

                    // Write server-side record message
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
                    // Write client-side record message
                    else if(pc > 0 && (ps == 0 || rc < rs))
                    {
                        // Extract server name indication
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

                            // Extension parsing
                            for(; spt + 4 <= ext_bound; )
                            {
                                // Extension type 0 : server name indication 
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

                            // Write conversation infos
                            // (1) source ip:port
                            // (2) destination ip:port
                            // (3) server name
                            // (4) stream index
                            // (5) #records
                            fprintf(fw, "%s:%d,%s:%d,%s,%.8d,%d\n",
                                cIP, fwd->port, sIP, rev->port, (sni[0] == '\0' ? "none" : sni),
                                ss_idx, fwd->rcd_cnt + rev->rcd_cnt);
                            
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