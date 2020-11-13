/* reader.cpp
 * 
 * routines for reading packet from a pcap file or interface
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "reader.h"
#include "handler.h"

namespace pump
{

    PcapReader::PcapReader(const char* pcapFileName) : Reader()
    {
        prdr_Name = new char[strlen(pcapFileName)+1];
        strcpy(prdr_Name, pcapFileName);
    }

    bool PcapReader::open()
    {
        if (rdr_PcapDescriptor != NULL)
        {
            WRITE_LOG("###WARNING : PcapReader is already opened");
            return true;
        }

        char errbuf[PCAP_ERRBUF_SIZE];

        rdr_PcapDescriptor = pcap_open_offline(prdr_Name, errbuf);
        if (rdr_PcapDescriptor == NULL)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not open a pcap file by provided name");
        }

        prdr_LinkLayerType = static_cast<uint16_t>(pcap_datalink(rdr_PcapDescriptor));

        rdr_ReaderOn = true;
        WRITE_LOG("===PcapReader is now scheduled to scan '%s'", prdr_Name);

        return true;
    }
    
    bool PcapReader::getNextPacket(Packet& packet)
    {
        packet.clear();
        if (rdr_PcapDescriptor == NULL)
        {
            EXIT_WITH_RUNERROR("###ERROR : PcapReader '%s' is not opened", prdr_Name);
        }
        
        pcap_pkthdr pkthdr;
        const uint8_t* pPacketData = pcap_next(rdr_PcapDescriptor, &pkthdr);

        if (pPacketData == NULL)
        {
            WRITE_LOG("===PcapReader '%s' encountered End-of-File (EOF)", prdr_Name);
            return false;
        }
        
        uint8_t* pMyPacketData = new uint8_t[pkthdr.caplen];
        memcpy(pMyPacketData, pPacketData, pkthdr.caplen);

        if (!packet.setRawData(pMyPacketData, pkthdr.caplen, pkthdr.ts, static_cast<uint16_t>(prdr_LinkLayerType)))
        {
            EXIT_WITH_RUNERROR("###ERROR : PcapReader '%s' is failed to read raw packet data", prdr_Name);
        }

        return true;
    }

    void PcapReader::close()
    {
        if (prdr_Name != NULL)
            delete [] prdr_Name;

        if (rdr_PcapDescriptor != NULL)
        {
            pcap_close(rdr_PcapDescriptor);
            rdr_PcapDescriptor = NULL;
        }

        rdr_ReaderOn = false;
    }

    pcap_t* LiveReader::doOpen()
    {
        char errbuf[PCAP_ERRBUF_SIZE] = {'\0'};
        pcap_t* pcap = pcap_create(lrdr_Name, errbuf);
        if (!pcap)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not access the network interface : %s", errbuf); 
        }
        
        int ret = pcap_set_snaplen(pcap, DEFAULT_SNAPLEN);
        if (ret != 0)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not access the network interface : %s", pcap_geterr(pcap)); 
        }

        ret = pcap_set_promisc(pcap, DEFAULT_DEVMODE);
        if (ret != 0)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not access the network interface : %s", pcap_geterr(pcap));
        }

        ret = pcap_set_timeout(pcap, DEFAULT_TIMEOUT);
        if (ret != 0)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not access the network interface : %s", pcap_geterr(pcap));
        }

        ret = pcap_activate(pcap);
        if (ret != 0)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not access the network interface : %s", pcap_geterr(pcap));
        }

        if (pcap)
        {
            int dlt = pcap_datalink(pcap);
            lrdr_LinkLayerType = (uint16_t)dlt;
        }
        return pcap;
    }

    void* LiveReader::captureThreadMain(void* ptr)
    {
        LiveReader* pThis = (LiveReader*)ptr;

        if (pThis == NULL) exit(1);

        while (!pThis->lrdr_StopThread)
        {
            pcap_dispatch(pThis->rdr_PcapDescriptor, -1, onPacketArrives, (uint8_t*)pThis);
        }

        return 0;
    }

    void LiveReader::onPacketArrives(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* packet)
    {
        LiveReader* pThis = (LiveReader*)user;

        if (pThis == NULL) exit(1);

        Packet Packet(packet, pkthdr->caplen, pkthdr->ts, false, pThis->getLinkLayerType());

        if (pThis->lrdr_cbOnPacketArrives != NULL)
            pThis->lrdr_cbOnPacketArrives(&Packet, pThis, pThis->lrdr_cbOnPacketArrivesUserCookie);
    }

    LiveReader::LiveReader(pcap_if_t* pInterface, bool calculateMTU, bool calculateMacAddress, bool calculateDefaultGateway) : Reader()
    {
        lrdr_Name = NULL;
        lrdr_LinkLayerType = LINKTYPE_ETHERNET;

        int strLength = strlen(pInterface->name)+1;
        lrdr_Name = new char[strLength];
        strncpy((char*)lrdr_Name, pInterface->name, strLength);

        while (pInterface->addresses != NULL)
        {
            pInterface->addresses = pInterface->addresses->next;
            if (pInterface->addresses != NULL && pInterface->addresses->addr != NULL)
            {
                char addrAsString[INET6_ADDRSTRLEN];
                sockaddr2string(pInterface->addresses->addr, addrAsString);
            }
        }
        lrdr_CaptureThreadOn = false;
        lrdr_StopThread = false;
        lrdr_cbOnPacketArrives = NULL;
        lrdr_cbOnPacketArrivesUserCookie = NULL;
    }
    
    bool LiveReader::open()
    {
        if (rdr_PcapDescriptor != NULL)
        {
            WRITE_LOG("###WARNING : LiveReader is already opened");
            return true;
        }

        rdr_PcapDescriptor = doOpen();
        if (rdr_PcapDescriptor == NULL)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not find interface by provided name");
        }

        rdr_ReaderOn = true;
        WRITE_LOG("===PcapReader is now scheduled to scan '%s'", lrdr_Name);
        return true;
    }

    void LiveReader::startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie)
    {
        if (!rdr_ReaderOn || rdr_PcapDescriptor == NULL)
        {
            EXIT_WITH_RUNERROR("###ERROR : LiveReader '%s' is not opened", lrdr_Name);
        }

        if (lrdr_CaptureThreadOn)
        {
            EXIT_WITH_RUNERROR("###ERROR : LiveReader '%s' is already capturing packets", lrdr_Name);
        }

        lrdr_cbOnPacketArrives = onPacketArrives;
        lrdr_cbOnPacketArrivesUserCookie = onPacketArrivesUserCookie;

        int err = pthread_create(&lrdr_CaptureThread, NULL, captureThreadMain, (void*)this);
        if (err != 0)
        {
            EXIT_WITH_RUNERROR("###ERROR : Could not create real-time capture thread for LiveReader '%s'", lrdr_Name);
        }
        lrdr_CaptureThreadOn = true;
    }

    void LiveReader::stopCapture()
    {
        lrdr_StopThread = true;
        if (lrdr_CaptureThreadOn)
        {
            pthread_join(lrdr_CaptureThread, NULL);
            lrdr_CaptureThreadOn = false;
        }

        sleep(1);
        lrdr_StopThread = false;
    }

    void LiveReader::close()
    {
        if (lrdr_Name != NULL)
            delete [] lrdr_Name;

        if (rdr_PcapDescriptor != NULL){
            pcap_close(rdr_PcapDescriptor);
            rdr_PcapDescriptor = NULL;
        }

        rdr_ReaderOn = false;
    }

    LiveInterfaces::LiveInterfaces()
    {
        pcap_if_t* interfaceList;
        char errbuf[PCAP_ERRBUF_SIZE];
        int err = pcap_findalldevs(&interfaceList, errbuf);
        if (err < 0)
        {
            EXIT_WITH_CONFERROR("###ERROR : Could not find activated network interfaces : %s", errbuf );
        }

        pcap_if_t* currInterface = interfaceList;
        while (currInterface != NULL)
        {
            LiveReader* dev = new LiveReader(currInterface, true, true, true);
            currInterface = currInterface->next;
            li_InterfaceList.insert(li_InterfaceList.end(), dev);
        }

        pcap_freealldevs(interfaceList);
    }

    LiveReader* LiveInterfaces::getLiveReader(const std::string& name) const
    {
        WRITE_LOG("===Search all live interfaces");
        for(std::vector<LiveReader*>::const_iterator devIter = li_InterfaceList.begin(); devIter != li_InterfaceList.end(); devIter++)
        {
            std::string devName((*devIter)->getName());
            if (name == devName)
                return (*devIter);
        }

        return NULL;
    }
}