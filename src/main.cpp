/* main.cpp
 * 
 * routines for capturing a series of SSL/TLS record data from TCP data streams
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h> 

#include "utils.h"
#include "reader.h"
#include "handler.h"
#include "assembly.h"

#define EXIT_WITH_OPTERROR(reason, ...) do { \
	printf("\n " reason "\n", ## __VA_ARGS__); \
    printUsage(); \
	exit(1); \
} while(0)

struct timeval init_tv;

static struct option TLSniffOptions[] =
{
    {"count",  required_argument, 0, 'c'},
    {"duration",  required_argument, 0, 'd'},
    {"interface",  required_argument, 0, 'i'},
    {"rcd-count", required_argument, 0, 'm'},
    {"rcd-count-perflow",  required_argument, 0, 'l'},
    {"input-file",  required_argument, 0, 'r'},
    {"output-file", required_argument, 0, 'w'},
    {"quite-mode", no_argument, 0, 'q'},
    {"byte-type", no_argument, 0, 'x'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

struct PacketArrivedData
{
    pump::Assembly* assembly;
    struct pump::CaptureConfig* config;
};

void printUsage()
{
    printf("\nTLSniff - a fast and simple tool to analyze SSL/TLS records\n"
    "See https://github.com/Cvilian/TLSniff for more information\n\n"
    "Usage: tlsniff [options] ...\n"
    "Capture packets:\n"
    "    -i <interface>   : Name of the network interface\n"
    "    -r <input-file>  : Read packet data from <input-file>\n"
    "Capture stop conditions:\n"
    "    -c <count>       : Set the maximum number of packets to read\n"
    "    -d <duration>    : Stop after <duration> seconds\n"
    "    -m <rcd count>   : Set the maximum number of records to read\n"
    "Processing:\n"
    "    -l <rcd count>   : Set the maximum number of records to be extracted per flow\n"
    "    -q               : Print less-verbose record information\n"
    "    -x               : Write <output-file> in hexadecimal form\n"
    "Output:\n"
    "    -w <output-file> : Write all SSL/TLS record data to <output-file>\n"
    "                       (or write its results to stdout)\n"
    "Others:\n"
    "    -h               : Displays this help message and exits\n"

    "-------------------------\n");
    exit(0);
}

void packetArrive(pump::Packet* packet, pump::LiveReader* rdr, void* cookie)
{
    PacketArrivedData* data = (PacketArrivedData*)cookie;
    data->assembly->managePacket(packet, data->config);
}

void doTLSniffOnLive(pump::LiveReader* rdr, struct pump::CaptureConfig* config)
{
    if (!rdr->open())
        EXIT_WITH_CONFERROR("###ERROR : Could not open the device");

    PacketArrivedData data;
    pump::Assembly assembly(init_tv);
    data.assembly = &assembly;
    data.config = config;
    rdr->startCapture(packetArrive, &data);

    // run in an endless loop until the user presses ctrl+c
    while(!assembly.isTerminated())
        sleep(1);

    rdr->stopCapture();

    if(!(config->quitemode)) printf("\n");
    pump::print_progressM(assembly.getTotalPacket());
    printf(" **%lu Bytes**\n", assembly.getTotalByteLen());

    if(config->outputFileTo != "")
    {
        assembly.registerEvent();
        assembly.mergeRecord(config);
    }

    assembly.close();
    delete rdr;
}

void doTLSniffOnPcap(std::string pcapFile, struct pump::CaptureConfig* config)
{
    pump::PcapReader* rdr = pump::PcapReader::getReader(pcapFile.c_str());
    
    if (!rdr->open())
        EXIT_WITH_CONFERROR("###ERROR : Could not open input pcap file");

    pump::Assembly assembly(init_tv);
    pump::Packet packet;

    while(rdr->getNextPacket(packet) && !assembly.isTerminated())
    {
        assembly.managePacket(&packet, config);
    }

    if(!(config->quitemode)) printf("\n");
    pump::print_progressM(assembly.getTotalPacket());
    printf(" **%lu Bytes**\n", assembly.getTotalByteLen());

    if(config->outputFileTo != "")
    {
        assembly.registerEvent();
        assembly.mergeRecord(config);
    }

    assembly.close();
    delete rdr;
}

int main(int argc, char* argv[])
{
    gettimeofday(&init_tv, NULL);

    if (getuid())
        EXIT_WITH_CONFERROR("###ERROR : Running TLSniff requires root privileges!\n");

    std::string readPacketsFromPcap = "";
    std::string readPacketsFromInterface = "";
    std::string outputFileTo = "";

    int optionIndex = 0;
    uint32_t maxPacket = IN_LIMIT;
    uint32_t maxTime = IN_LIMIT;
    uint32_t maxRcd = IN_LIMIT;
    uint32_t maxRcdpf = IN_LIMIT;
    bool outputTypeHex = false;
    bool quitemode = false;
    char opt = 0;

    while((opt = getopt_long (argc, argv, "c:d:i:l:m:r:w:qxh", TLSniffOptions, &optionIndex)) != -1)
    {
        switch (opt)
        {
            case 0:
                break;
            case 'c':
                maxPacket = atoi(optarg);
                break;
            case 'd':
                maxTime = atoi(optarg);
                break;
            case 'i':
                readPacketsFromInterface = optarg;
                break;
            case 'l':
                maxRcdpf = atoi(optarg);
                break;
            case 'm':
                maxRcd = atoi(optarg);
                break;
            case 'r':
                readPacketsFromPcap = optarg;
                break;
            case 'w':
                outputFileTo = optarg;
                break;
            case 'q':
                quitemode = true;
                break;
            case 'x':
                outputTypeHex = true;
                break;
            case 'h':
                printUsage();
                break;
            default:
                printUsage();
                exit(-1);
        }
    }

    // if no input pcap file or network interface was provided - exit with error
    if (readPacketsFromPcap == "" && readPacketsFromInterface == "")
        EXIT_WITH_OPTERROR("###ERROR : Neither interface nor input pcap file were provided");

    // you should choose only one option : pcap or interface - exit with error
    if (readPacketsFromPcap != "" && readPacketsFromInterface != "")
        EXIT_WITH_OPTERROR("###ERROR : Choose only one option, pcap or interface");

    if (maxPacket <= 0)
        EXIT_WITH_OPTERROR("###ERROR : #Packet can't be a non-positive integer");

    if (maxTime <= 0)
        EXIT_WITH_OPTERROR("###ERROR : Duration can't be a non-positive integer");

    if (maxRcd <= 0)
        EXIT_WITH_OPTERROR("###ERROR : #Record can't be a non-positive integer");

    if (maxRcdpf <= 0)
        EXIT_WITH_OPTERROR("###ERROR : #Record per flow can't be a non-positive integer");

    struct pump::CaptureConfig config = {
        .maxPacket = maxPacket,
        .maxTime = maxTime,
        .maxRcd = maxRcd,
        .maxRcdpf = maxRcdpf,
        .outputTypeHex = outputTypeHex,
        .quitemode = quitemode,
        .outputFileTo = outputFileTo
    };

    if(access(saveDir.c_str(), 0) == -1)
        mkdir(saveDir.c_str(), 0777);

    if (readPacketsFromPcap != "")
    {
        doTLSniffOnPcap(readPacketsFromPcap, &config);
    }
    else
    {
        pump::LiveReader* rdr = pump::LiveInterfaces::getInstance().getLiveReader(readPacketsFromInterface);

        if (rdr == NULL)
            EXIT_WITH_CONFERROR("###ERROR : Couldn't find interface by provided name");

        doTLSniffOnLive(rdr, &config);
    }
    pump::clearTLSniff();
    printf(" **All Done**\n");
    WRITE_LOG("===Process Finished");
    return 0;
}