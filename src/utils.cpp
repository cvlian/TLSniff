/* utils.cpp
 *
 * define common functionalities
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records  
 */

#include <stdio.h>

#include "utils.h"

namespace pump
{

    uint32_t fnv_hash(ScalarBuffer vec[], size_t vecSize)
    {
        uint32_t hash = OFFSET_BASIS;
        for (size_t i = 0; i < vecSize; i++)
        {
            for (size_t j = 0; j < vec[i].len; j++)
            {
                hash *= FNV_PRIME;
                hash ^= vec[i].buffer[j];
            }
        }
        return hash;
    }

    void parseIPV4(char* s, uint32_t ip_addr)
    {
        sprintf(s, "%d.%d.%d.%d", (ip_addr >> 24) & 0xFF, (ip_addr >> 16) & 0xFF, (ip_addr >>  8) & 0xFF, ip_addr & 0xFF);
    }

    int64_t time_diff(timeval* tv1, timeval* tv2)
    {
        return time_raw(tv1) - time_raw(tv2);
    }

    int64_t time_raw(timeval* tv)
    {
        return 1000000 * (int64_t)tv->tv_sec + (int64_t)tv->tv_usec;
    }

    void time_update(timeval* tv1, timeval* tv2)
    {
        tv1->tv_usec = tv2->tv_usec;
        tv1->tv_sec = tv2->tv_sec;
    }

    void print_progressM(uint32_t c)
    {
        printf("\r**Capture Packets**========================================= (%u)", c);
        fflush(stdout);
    }

    void print_progressA(uint32_t s, uint32_t ts)
    {
        printf("\r**Reassemble Streams**====================================== (%d/%d) ", s, ts);
        fflush(stdout);
    }

}