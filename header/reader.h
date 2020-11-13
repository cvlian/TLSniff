/* reader.h
 * 
 * routines for reading packet from a pcap file or interface
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#ifndef PUMP_READER
#define PUMP_READER

#include <pcap.h>
#include <stdint.h>

#include "packet.h"
#include "layer-ip4.h"

static const int DEFAULT_DEVMODE = 1;
static const int DEFAULT_SNAPLEN = 9000;
static const int DEFAULT_TIMEOUT = -1;

namespace pump
{

    class LiveReader;

    typedef void (*OnPacketArrivesCallback)(Packet* packet, LiveReader* lrdr, void* userCookie);

    typedef bool (*OnPacketArrivesStopBlocking)(Packet* packet, LiveReader* lrdr, void* userData);

    typedef void* (*ThreadStart)(void*);

    class Reader
    {

        protected:

            bool rdr_ReaderOn;
            pcap_t* rdr_PcapDescriptor;

            Reader() { rdr_ReaderOn = false; rdr_PcapDescriptor = NULL; }
        
        public:

            virtual ~Reader() {}

            virtual bool open() = 0;

            virtual void close() = 0;

    };

    class PcapReader : public Reader
    {

        protected:

            char* prdr_Name;
            uint16_t prdr_LinkLayerType;

        public:

            PcapReader(const char* pcapFileName);

            ~PcapReader() { close(); }

            bool open();

            bool getNextPacket(Packet& packet);

            void close();

    };

    class LiveReader : public Reader
    {

        friend class LiveInterfaces;

        protected:

            char* lrdr_Name;
            uint16_t lrdr_LinkLayerType;
            bool lrdr_CaptureThreadOn;
            bool lrdr_StopThread;
            OnPacketArrivesCallback lrdr_cbOnPacketArrives;
            void* lrdr_cbOnPacketArrivesUserCookie;
            pthread_t lrdr_CaptureThread;

            pcap_t* doOpen();
            static void* captureThreadMain(void* ptr);
            static void onPacketArrives(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* packet);

        public:

            LiveReader(pcap_if_t* pInterface, bool calculateMTU, bool calculateMacAddress, bool calculateDefaultGateway);

            ~LiveReader() { close(); }

            bool open();

            void startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie);

            void stopCapture();

            const char* getName() const { return lrdr_Name; }

            uint getLinkLayerType() const { return lrdr_LinkLayerType; }

            void close();

    };

    class LiveInterfaces
    {

        private:

            std::vector<LiveReader*> li_InterfaceList;

            LiveInterfaces();

        public:

            static LiveInterfaces& getInstance()
            {
                static LiveInterfaces instance;
                return instance;
            }

            LiveReader* getLiveReader(const std::string& name) const;

    };

}

#endif