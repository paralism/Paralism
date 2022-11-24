/*Copyright 2016-2022 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this? software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED,? INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#pragma once

#include <cstdarg>
#include <string>
#include <vector>

std::string strprintf(const char* fmt, ...);
std::string currentTime();
int64_t currentMillisecond();

template<class Container>
std::string ToHexString(const Container& container)
{
    std::string rs;
    rs.resize(container.size() * 2);

    char* p = &rs[0];
    for (unsigned char c : container) {
        sprintf(p, "%02x", c);
        p += 2;
    }
    return  rs;
}

//////////////////////////////////////////////////////////////////////////
/// log
void log_output_nowrap(const char* format, ...);

extern bool fPrintgrep;
extern std::vector<std::string> vecgreps;


extern int OutputDebugStringF(const char* pszFormat, ...);

template<const char* C, bool R>
bool vlog_output(const char* format, va_list arg_ptr)
{
    va_list argstmp;
    va_copy(argstmp, arg_ptr);

    int sz = std::vsnprintf(nullptr, 0, format, arg_ptr);

    std::string buf(sz + 1, 0);
    std::vsnprintf(&buf[0], sz + 1, format, argstmp);
    va_end(argstmp);

    if (fPrintgrep) {
        bool isOutput = false;
        for (auto & str : vecgreps) {
            if (buf.find(str) != std::string::npos) {
                isOutput = true;
                break;
            }
        }
        if (!isOutput) {
            return R;
        }
    }
    OutputDebugStringF("%s: %s\n", C, buf.c_str());
    return R;
}


template<const char* C, bool R>
bool log_output(const char* format, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, format);
    vlog_output<C, R>(format, arg_ptr);
    va_end(arg_ptr);

    return R;
}

enum class LOGLEVEL : char
{
    L_TRACE,
    L_DEBUG,
    L_INFO,
    L_WARNING,
    L_ERROR,
    L_NONE,
};

extern LOGLEVEL floglevel;
extern char log_prefix_t[];
extern char log_prefix_d[];
extern char log_prefix_i[];
extern char log_prefix_e[];
extern char log_prefix_w[];
extern char mdname[]; //module name

extern bool fPrintToConsole;
extern bool fPrintToDebugFile;

inline bool canDump()
{
    return fPrintToConsole || fPrintToDebugFile;
}

#define __formatex(fmt) "%s (%s!%s:%d) " fmt, currentTime().c_str(), mdname, __FUNCTION__, __LINE__

#define TRACE_NOWRAP(fmt, ...) if(floglevel <= LOGLEVEL::L_TRACE && canDump()) log_output_nowrap((fmt), ##__VA_ARGS__)

#define DEBUG_NOWRAP(fmt, ...) if(floglevel <= LOGLEVEL::L_DEBUG && canDump()) log_output_nowrap((fmt), ##__VA_ARGS__)

#define INFO_NOWRAP(fmt, ...) if(floglevel <= LOGLEVEL::L_INFO && canDump()) log_output_nowrap((fmt), ##__VA_ARGS__)

#define TRACE_FL(fmt, ...) \
    (floglevel <= LOGLEVEL::L_TRACE && canDump()) ? \
        log_output<log_prefix_t, true>(__formatex(fmt), ##__VA_ARGS__) : true

#define DEBUG_FL(fmt, ...) \
    (floglevel <= LOGLEVEL::L_DEBUG && canDump()) ? \
        log_output<log_prefix_d, true>(__formatex(fmt), ##__VA_ARGS__) : true

#define INFO_FL(fmt, ...) \
    (floglevel <= LOGLEVEL::L_INFO && canDump()) ? \
        log_output<log_prefix_i, true>(__formatex(fmt), ##__VA_ARGS__) : true

#define WARNING_FL(fmt, ...) \
    (floglevel <= LOGLEVEL::L_WARNING && canDump()) ? \
        log_output<log_prefix_w, false>(__formatex(fmt), ##__VA_ARGS__) : false

#define ERROR_FL(fmt, ...) \
    (canDump() && floglevel <= LOGLEVEL::L_ERROR) ? \
        log_output<log_prefix_e, false>(__formatex(fmt), ##__VA_ARGS__) : false

#define LogRequestFromNode(fromnode, fmt, ...) \
    if(fPrintBacktracking_node && fromnode == strBacktracking_node) { \
        LogBacktracking(__formatex(fmt), ##__VA_ARGS__); \
    }

#define LogRequest(fmt, ...) \
    if(fPrintBacktracking) { \
        LogBacktracking(__formatex(fmt), ##__VA_ARGS__); \
    }
