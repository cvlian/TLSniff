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
    {"input-file",  required_argument, 0, 'r'},
    {"output-file", required_argument, 0, 'o'},
    {"byte-type", no_argument, 0, 'x'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

struct TLSPacketArrivedData
{
    pump::Assembly* assembly;
    struct pump::CaptureConfig* config;
};

void printUsage()
{
    printf("\nUsage:\n"
    "----------------------\n"
    "tlsniff [-h] [-c #packet] [-d duration] [-m #record] [-i interface / -r input_file] -o output_file [-x]\n"
    "\nOptions:\n\n"
    "    -c <count>       : Set the maximum number of packets to read\n"
    "    -d <duration>    : Stop after <duration> seconds\n"
    "    -i <interface>   : Name of the network interface\n"
    "    -m <rcd count>   : Set the maximum number of records to read\n"
    "    -r <input-file>  : Read packet data from <input-file>\n"
    "    -o <output-file> : Write all SSL/TLS record data to <output-file>\n"
    "    -x               : Write <output-file> in hexadecimal form\n"
    "    -h               : Displays this help message and exits\n"
    "-------------------------\n");
    exit(0);
}

void packetArrive(pump::Packet* packet, pump::LiveReader* rdr, void* cookie)
{
    TLSPacketArrivedData* data = (TLSPacketArrivedData*)cookie;
    data->assembly->managePacket(packet, data->config);
}

void doTLSniffOnLive(pump::LiveReader* rdr, struct pump::CaptureConfig* config)
{
    if (!rdr->open())
        EXIT_WITH_CONFERROR("###ERROR : Could not open the device");

    TLSPacketArrivedData data;
    pump::Assembly assembly(init_tv);
    data.assembly = &assembly;
    data.config = config;
    rdr->startCapture(packetArrive, &data);

    // run in an endless loop until the user presses ctrl+c
    while(!assembly.isTerminated())
        sleep(1);

    rdr->stopCapture();
    rdr->close();

    assembly.registerEvent();

    pump::print_progressM(assembly.getTotalPacket());
    printf(" **%lu Bytes**\n", assembly.getTotalByteLen());

    assembly.mergeRecord(config);
}

void doTLSniffOnPcap(std::string pcapFile, struct pump::CaptureConfig* config)
{
    pump::PcapReader rdr(pcapFile.c_str());
    if (!rdr.open())
        EXIT_WITH_CONFERROR("###ERROR : Could not open input pcap file");

    pump::Assembly assembly(init_tv);
    pump::Packet packet;

    while(rdr.getNextPacket(packet) && !assembly.isTerminated())
    {
        assembly.managePacket(&packet, config);
    }

    rdr.close();

    assembly.registerEvent();
    pump::print_progressM(assembly.getTotalPacket());
    printf(" **%lu Bytes**\n", assembly.getTotalByteLen());

    assembly.mergeRecord(config);
}

int main(int argc, char* argv[])
{
    gettimeofday(&init_tv, NULL);

    if (getuid())
        EXIT_WITH_CONFERROR("###ERROR : Would recommend NOT running this program as non-root user!\n");

    std::string readPacketsFromPcap = "";
    std::string readPacketsFromInterface = "";
    std::string outputFileTo = "";

    int optionIndex = 0;
    uint32_t maxPacket = IN_LIMIT;
    uint32_t maxTime = IN_LIMIT;
    uint32_t maxRcd = IN_LIMIT;
    bool outputTypeHex = false;
    char opt = 0;

    while((opt = getopt_long (argc, argv, "c:d:i:m:r:o:xh", TLSniffOptions, &optionIndex)) != -1)
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
            case 'm':
                maxRcd = atoi(optarg);
                break;
            case 'r':
                readPacketsFromPcap = optarg;
                break;
            case 'o':
                outputFileTo = optarg;
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

    if (outputFileTo == "")
        EXIT_WITH_OPTERROR("###ERROR : Output file was not provided");

    if (maxPacket <= 0)
        EXIT_WITH_OPTERROR("###ERROR : #Packet can't be a non-positive integer");

    if (maxTime <= 0)
        EXIT_WITH_OPTERROR("###ERROR : Duration can't be a non-positive integer");

    if (maxRcd <= 0)
        EXIT_WITH_OPTERROR("###ERROR : #Record per flow can't be a non-positive integer");

    struct pump::CaptureConfig config = {
        .maxPacket = maxPacket,
        .maxTime = maxTime,
        .maxRcd = maxRcd,
        .outputTypeHex = outputTypeHex,
        .saveDir = saveDir,
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