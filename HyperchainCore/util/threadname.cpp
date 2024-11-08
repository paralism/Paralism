//

#include "threadname.h"


//HC: usage:
//std::thread th([]()
//    {
//        SetThreadName(-1, "name");
//        std::this_thread::sleep_for(std::chrono::seconds(1000));
//    });

namespace hc {

#ifdef WIN32
typedef struct tagTHREADNAME_INFO
{
    DWORD dwType;   // must be 0x1000
    LPCSTR szName;  // pointer to name (in user addr space)
    DWORD dwThreadID; // thread ID (-1=caller thread)
    DWORD dwFlags;  // reserved for future use, must be zero
} THREADNAME_INFO;


void SetThreadName(DWORD dwThreadID, LPCSTR szThreadName)
{
    THREADNAME_INFO info;
    info.dwType = 0x1000;
    info.szName = szThreadName;
    info.dwThreadID = dwThreadID;
    info.dwFlags = 0;

    //The native method of setting the thread name is implemented by raising an SEH exception that is continued.
    //If you go to the docs on RaiseException you'll see part of the reason for this strange mechanism.
    //An attached native debugger will get a 'first chance' notification of the exception.
    //Raising an exception is precisely what you need to do to get the native debugger's attention.
    //The one raised here(0x406D1388) is recognized by VS(and WinDbg).
    __try
    {
        RaiseException(0x406D1388, 0, sizeof(info) / sizeof(DWORD), (ULONG_PTR*)&info);
    }
    __except (EXCEPTION_CONTINUE_EXECUTION)
    {
    }
}

void SetThreadName(std::thread *t, LPCSTR szThreadName)
{
    DWORD id = ::GetThreadId(t->native_handle());
    SetThreadName(id, szThreadName);
}

#else


void SetThreadName(pthread_t thread, const char* name)
{
    if (thread == -1)
        prctl(PR_SET_NAME, name);
    else
        pthread_setname_np(thread, name);
}

void SetThreadName(std::thread *t, const char* name)
{
    SetThreadName(t->native_handle(), name);
}


#endif

}
