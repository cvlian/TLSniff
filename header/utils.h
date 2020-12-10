/* utils.h
 *
 * define common functionalities
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records  
 */

#ifndef PUMP_UTILS
#define PUMP_UTILS

#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>

static const uint32_t FNV_PRIME = 16777619u;
static const uint32_t OFFSET_BASIS = 2166136261u;

static const uint32_t IN_LIMIT = 1073741824u;
static const int maxbuf = 65536;
static const long MEMORY_LIMIT = 8*1024*1024;

namespace pump
{

    struct ScalarBuffer
    {
        uint8_t* buffer;
        size_t len;
    };

    uint32_t fnv_hash(ScalarBuffer vec[], size_t vecSize);

    void parseIPV4(char* s, uint32_t ip_addr);

    int64_t time_diff(timeval* tv1, timeval* tv2);

    int64_t time_raw(timeval* tv);

    void time_update(timeval* tv1, timeval* tv2);

    void print_progressM(uint32_t c);

    void print_progressA(uint32_t s, uint32_t ts);

    void print_progressC(uint32_t c);

}

#endif