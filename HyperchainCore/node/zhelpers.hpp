/*Copyright 2016-2022 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#pragma once

//HC: Include a bunch of headers that we will need in the examples

#include <zmq.hpp>

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>

#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#if (!defined(WIN32))
#   include <sys/time.h>
#   include <unistd.h>
#else
#include <windows.h>
#endif

#include <string>
using namespace std;

//HC: Bring Windows MSVC up to C99 scratch
#if (defined (WIN32))
typedef unsigned long ulong;
typedef unsigned int  uint;
typedef __int64 int64_t;
#endif

//HC: On some version of Windows, POSIX subsystem is not installed by default.
//HC: So define srandom and random ourself.
//
#if (defined (WIN32))
#   define srandom srand
#   define random rand
#endif

//HC: Visual Studio versions below 2015 do not support sprintf properly. This is a workaround.
//HC: Taken from http://stackoverflow.com/questions/2915672/snprintf-and-visual-studio-2010
#if defined(_MSC_VER) && _MSC_VER < 1900

#define snprintf c99_snprintf
#define vsnprintf c99_vsnprintf

inline int c99_vsnprintf(char *outBuf, size_t size, const char *format, va_list ap)
{
    int count = -1;

    if (size != 0)
        count = _vsnprintf_s(outBuf, size, _TRUNCATE, format, ap);
    if (count == -1)
        count = _vscprintf(format, ap);

    return count;
}

inline int c99_snprintf(char *outBuf, size_t size, const char *format, ...)
{
    int count;
    va_list ap;

    va_start(ap, format);
    count = c99_vsnprintf(outBuf, size, format, ap);
    va_end(ap);

    return count;
}

#endif

//HC: Provide random number from 0..(num-1)
#define within(num) (int) ((float)((num) * random ()) / (RAND_MAX + 1.0))

//HC: Receive 0MQ string from socket and convert into C string
//HC: Caller must free returned string.
inline static char *
s_recv(void *socket, int flags = 0)
{
    zmq_msg_t message;
    zmq_msg_init(&message);

    int rc = zmq_msg_recv(&message, socket, flags);

    if (rc < 0)
        return nullptr;           //HC: Context terminated, exit

    size_t size = zmq_msg_size(&message);
    char *string = (char*)malloc(size + 1);
    memcpy(string, zmq_msg_data(&message), size);
    zmq_msg_close(&message);
    string[size] = 0;
    return (string);
}

//HC: Receive 0MQ string from socket and convert into string
inline static std::string
s_recv(zmq::socket_t & socket, int flags = 0)
{
    zmq::message_t message;
    socket.recv(message, (zmq::recv_flags)flags);

    return std::string(static_cast<char*>(message.data()), message.size());
}

inline static bool s_recv(zmq::socket_t & socket, std::string & ostring, int flags = 0)
{
    zmq::message_t message;
    auto rc = socket.recv(message, (zmq::recv_flags)flags);

    if (rc) {
        ostring = std::string(static_cast<char*>(message.data()), message.size());
        return true;
    }

    return false;
}

//HC: Convert C string to 0MQ string and send to socket
inline static int
s_send(void *socket, const char *string, int flags = 0)
{
    int rc;
    zmq_msg_t message;
    zmq_msg_init_size(&message, strlen(string));
    memcpy(zmq_msg_data(&message), string, strlen(string));
    rc = zmq_msg_send(&message, socket, flags);
    assert(-1 != rc);
    zmq_msg_close(&message);
    return (rc);
}

//HC: Convert string to 0MQ string and send to socket
inline static bool
s_send(zmq::socket_t & socket, const std::string & string, int flags = 0)
{

    zmq::message_t message(string.size());
    memcpy(message.data(), string.data(), string.size());

    auto rc = socket.send(message, (zmq::send_flags)flags);
    if (rc)
        return true;
    return false;
}

//HC: Sends string as 0MQ string, as multipart non-terminal
inline static int
s_sendmore(void *socket, char *string)
{
    int rc;
    zmq_msg_t message;
    zmq_msg_init_size(&message, strlen(string));
    memcpy(zmq_msg_data(&message), string, strlen(string));
    rc = zmq_msg_send(&message, socket, ZMQ_SNDMORE);
    assert(-1 != rc);
    zmq_msg_close(&message);
    return (rc);
}

//HC: Sends string as 0MQ string, as multipart non-terminal
inline static bool
s_sendmore(zmq::socket_t & socket, const std::string & string)
{
    zmq::message_t message(string.size());
    memcpy(message.data(), string.data(), string.size());

    auto rc = socket.send(std::move(message), zmq::send_flags::sndmore);
    if (rc)
        return true;
    return false;
}

//HC: Receives all message parts from socket, prints neatly
inline static void
s_dump(zmq::socket_t & socket)
{
    std::cout << "----------------------------------------" << std::endl;

    while (1) {
        //HC: Process all parts of the message
        zmq::message_t message;
        socket.recv(message);

        //HC: Dump the message as text or binary
        size_t size = message.size();
        std::string data(static_cast<char*>(message.data()), size);

        bool is_text = true;

        size_t char_nbr;
        unsigned char byte;
        for (char_nbr = 0; char_nbr < size; char_nbr++) {
            byte = data[char_nbr];
            if (byte < 32 || byte > 127)
                is_text = false;
        }
        std::cout << "[" << std::setfill('0') << std::setw(3) << size << "]";
        for (char_nbr = 0; char_nbr < size; char_nbr++) {
            if (is_text)
                std::cout << (char)data[char_nbr];
            else
                std::cout << std::setfill('0') << std::setw(2)
                << std::hex << (unsigned int)data[char_nbr];
        }
        std::cout << std::endl;

        int more = 0;           //HC: Multipart detection
        size_t more_size = sizeof(more);
        socket.getsockopt(ZMQ_RCVMORE, &more, &more_size);
        if (!more)
            break;              //HC: Last message part
    }
}

//HC: Return current system clock as milliseconds
inline static int64_t
s_clock(void)
{
#if (defined (WIN32))
    FILETIME fileTime;
    GetSystemTimeAsFileTime(&fileTime);
    unsigned __int64 largeInt = fileTime.dwHighDateTime;
    largeInt <<= 32;
    largeInt |= fileTime.dwLowDateTime;
    largeInt /= 10000; // FILETIME is in units of 100 nanoseconds
    return (int64_t)largeInt;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
#endif
}

inline std::string
s_set_id(zmq::socket_t & socket)
{
    std::stringstream ss;
    ss << std::hex << std::uppercase
        << std::setw(4) << std::setfill('0') << within(0x10000) << "-" << s_clock();
    socket.setsockopt(ZMQ_IDENTITY, ss.str().c_str(), ss.str().length());
    //socket.set(zmq::sockopt::subscribe, ss);
    return ss.str();
}

//HC: Report 0MQ version number
//
inline static void
s_version(void)
{
    int major, minor, patch;
    zmq_version(&major, &minor, &patch);
    std::cout << "Current 0MQ version is " << major << "." << minor << "." << patch << std::endl;
}

inline static void
s_version_assert(int want_major, int want_minor)
{
    int major, minor, patch;
    zmq_version(&major, &minor, &patch);
    if (major < want_major
        || (major == want_major && minor < want_minor)) {
        std::cout << "Current 0MQ version is " << major << "." << minor << std::endl;
        std::cout << "Application needs at least " << want_major << "." << want_minor
            << " - cannot continue" << std::endl;
        exit(EXIT_FAILURE);
    }
}


//HC: Sleep for a number of milliseconds
inline static void
s_sleep(int msecs)
{
#if (defined (WIN32))
    Sleep(msecs);
#else
    struct timespec t;
    t.tv_sec = msecs / 1000;
    t.tv_nsec = (msecs % 1000) * 1000000;
    nanosleep(&t, NULL);
#endif
}

inline
static string toReadable(int64_t nbytes)
{
    char szOutput[128] = { 0 };

    if (nbytes > 1024 * 1024 * 1024) {
         sprintf(szOutput, "%.2f(GB)", nbytes / 1024 / 1024 / 1024.0);
    }
    else if (nbytes > 1024 * 1024) {
        sprintf(szOutput, "%.2f(MB)", nbytes / 1024 / 1024.0);
    }
    else if (nbytes > 1024) {
        sprintf(szOutput, "%.2f(KB)", nbytes / 1024.0);
    }
    else
        sprintf(szOutput, "%d(B)", (int)nbytes);
    return string(szOutput);
}

//HC: no output year and second
inline static
std::string time2string_s(time_t time1)
{
    char szTime[128] = { 0 };
    struct tm tm1;
#ifdef WIN32
    localtime_s(&tm1, &time1);
#else
    localtime_r(&time1, &tm1);
#endif
    sprintf(szTime, "%2.2d-%2.2d %2.2d:%2.2d",
        tm1.tm_mon + 1, tm1.tm_mday,
        tm1.tm_hour, tm1.tm_min);
    return string(szTime);
}

inline static
std::string time2string(time_t time1)
{
    char szTime[128] = { 0 };
    struct tm tm1;
#ifdef WIN32
    localtime_s(&tm1, &time1);
#else
    localtime_r(&time1, &tm1);
#endif
    sprintf(szTime, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
        tm1.tm_year + 1900, tm1.tm_mon + 1, tm1.tm_mday,
        tm1.tm_hour, tm1.tm_min, tm1.tm_sec);
    return string(szTime);
}

inline static
std::string time2string()
{
    return time2string(time(nullptr));
}

inline static void
s_console(const char *format, ...)
{
    printf("%s ", time2string().c_str());

    va_list argptr;
    va_start(argptr, format);
    vprintf(format, argptr);
    va_end(argptr);
    printf("\n");
}

//  ---------------------------------------------------------------------
static int s_interrupted = 0;

#if (!defined(WIN32))

inline static void s_signal_handler(int signal_value)
{
    //UNUSED(signal_value)
    (void)(signal_value);
    s_interrupted = 1;
}

#else

inline static
BOOL WINAPI HandlerRoutine(_In_ DWORD dwCtrlType)
{
    switch (dwCtrlType) {
    case CTRL_C_EVENT:
        printf("[Ctrl]+C\n");
        s_interrupted = 1;
        //HC: Signal is handled - don't pass it on to the next handler
        return TRUE;
    default:
        //HC: Pass signal on to the next handler
        return FALSE;
    }
}

#endif

inline static void s_catch_signals()
{
#if (!defined(WIN32))

    struct sigaction action;
    action.sa_handler = s_signal_handler;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

#else

    if (!SetConsoleCtrlHandler(HandlerRoutine, TRUE)) {
        printf("\nERROR: Could not set control handler");
    }

#endif
}


