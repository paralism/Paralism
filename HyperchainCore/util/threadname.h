//
#pragma once


#ifdef WIN32
#include <windows.h>
#else
#include <sys/prctl.h>
#include <pthread.h>
#endif

#include <thread>

//HC: usage:
//std::thread th([]()
//    {
//        SetThreadName(-1, "name");
//        std::this_thread::sleep_for(std::chrono::seconds(1000));
//    });

namespace hc {

#ifdef WIN32
    void SetThreadName(DWORD dwThreadID, LPCSTR szThreadName);
    void SetThreadName(std::thread* t, LPCSTR szThreadName);
#else
    void SetThreadName(pthread_t thread, const char* name);
    void SetThreadName(std::thread* t, const char* name);
#endif

    void CreateThread(const char* threadname, void(*pfn)(void*), void* parg);

}
