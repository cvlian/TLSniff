/* handler.cpp
 * 
 * routines to catch several errors, sudden cessations
 *  
 * TLSniff - a fast and simple tool to analyze SSL/TLS records 
 */

#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>

#include "utils.h"
#include "handler.h"

namespace pump
{
    
    static pthread_mutex_t mutex;

    std::string currTime()
    {
        char buff[32];
        time_t t = time(NULL);
        struct tm ctm = *localtime(&t);
        sprintf(buff, "%.4d%.2d%.2d", ctm.tm_year + 1900, ctm.tm_mon + 1, ctm.tm_mday);
        return std::string(buff);
    }

    void clearTLSniff()
    {
        DIR *dir, *sub_dir;
        struct dirent *d, *sd;
        char sd_path[256] = {0}, file_path[512] = {0};
        uint32_t removed = 0;
        timeval ref_tv, print_tv = {0,0};

        if((dir = opendir(saveDir.c_str())) != NULL)
        {
            while((d = readdir(dir)) != NULL)
            {

                if(*(d->d_name) == '.') continue;

                gettimeofday(&ref_tv, NULL);

                if (time_diff(&ref_tv, &print_tv) >= 31250)
                {
                    print_progressC(removed);
                    time_update(&print_tv, &ref_tv);
                }

                sprintf(sd_path, "%s%s", saveDir.c_str(), d->d_name);

                if((sub_dir = opendir(sd_path)) != NULL)
                {
                    while((sd = readdir(sub_dir)) != NULL)
                    {
                        sprintf(file_path, "%s%s/%s", saveDir.c_str(), d->d_name, sd->d_name);
                        remove(file_path);
                    }
                    closedir(sub_dir);
                }
                rmdir(sd_path);
                ++removed;
            }
            closedir(dir);
        }
        rmdir(saveDir.c_str());
        printf("\r**Clear Stream Info**======================================= (%d) ", removed);
    }

    void EventHandler::handlerRoutine(int signum)
    {
        switch (signum)
        {
            case SIGINT:
            {
                pthread_mutex_lock(&mutex);

                if (EventHandler::getInstance().h_interrupt_handler != NULL)
                    EventHandler::getInstance().h_interrupt_handler(EventHandler::getInstance().h_interrupt_cookie);

                EventHandler::getInstance().h_interrupt_handler = NULL;

                pthread_mutex_unlock(&mutex);
                return;
            }
            default:
            {
                return;
            }
        }
    }

    void EventHandler::onInterrupted(EventHandlerCallback handler, void* cookie)
    {
        h_interrupt_handler = handler;
        h_interrupt_cookie = cookie;

        struct sigaction action;
        memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = handlerRoutine;
        sigemptyset(&action.sa_mask);
        sigaction(SIGINT, &action, NULL);
    }

}