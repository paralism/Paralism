/*Copyright 2016-2024 hyperchain.net (Hyperchain)

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

#include "plcommon.h"

#include <string>
#include <chrono>
#include <ctime>
#include <map>
#include <set>

using namespace std;

#include <boost/config.hpp>

LOGLEVEL floglevel = LOGLEVEL::L_CRITICAL;

char log_prefix_t[] = "TRACE";
char log_prefix_d[] = "DEBUG";
char log_prefix_i[] = "INFO";
char log_prefix_e[] = "ERROR";
char log_prefix_cr[] = "CRITICAL";
char log_prefix_w[] = "WARNING";

char log_prefix_bt[] = "Bt";        //HCE: backtracking
char log_prefix_btf[] = "BtfNode";  //HCE: backtracking from node

char log_prefix_cp[] = "CostParse";  //HCE: backtracking from node




int64_t currentMillisecond()
{
    auto tNow = std::chrono::system_clock::now();
    auto tMilli = std::chrono::duration_cast<std::chrono::milliseconds>(tNow.time_since_epoch());
    return tMilli.count();
}

std::string currentTime()
{
    auto tNow = std::chrono::system_clock::now();
    //auto t = std::time(nullptr);
    auto t = std::chrono::system_clock::to_time_t(tNow);

    auto tSeconds = std::chrono::duration_cast<std::chrono::seconds>(tNow.time_since_epoch());
    auto tMilli = std::chrono::duration_cast<std::chrono::milliseconds>(tNow.time_since_epoch());
    auto ms = tMilli - tSeconds;

    auto tmNow = *std::localtime(&t);
    return strprintf("%d-%02d-%02d %02d:%02d:%02d.%03d", tmNow.tm_year + 1900,
        tmNow.tm_mon + 1, tmNow.tm_mday, tmNow.tm_hour, tmNow.tm_min, tmNow.tm_sec, ms);
}

void log_output_nowrap(const char* format, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, format);
    int sz = std::vsnprintf(nullptr, 0, format, arg_ptr);
    va_end(arg_ptr);

    std::string buf(sz + 1, 0);

    va_start(arg_ptr, format);
    std::vsnprintf(&buf[0], sz + 1, format, arg_ptr);
    va_end(arg_ptr);

    fprintf(stdout, "%s", buf.c_str());
}

extern bool fPrintToConsole;
extern bool fPrintToDebugFile;
extern bool fPrintBacktracking;
extern bool fPrintBacktracking_node;
extern std::string strBacktracking_node;

extern bool fPrintCostParse;




void LogBacktracking(const char* format, ...)
{
    // print to console
    va_list arg_ptr;
    va_start(arg_ptr, format);
    vlog_output<log_prefix_bt, true>(format, arg_ptr);
    va_end(arg_ptr);
}

static map<LOGLEVEL, string> mapll = {
    {LOGLEVEL::L_NONE, "None"},
    {LOGLEVEL::L_TRACE, log_prefix_t},
    {LOGLEVEL::L_DEBUG, log_prefix_d},
    {LOGLEVEL::L_INFO, log_prefix_i },
    {LOGLEVEL::L_WARNING, log_prefix_w},
    {LOGLEVEL::L_ERROR, log_prefix_e},
    {LOGLEVEL::L_CRITICAL, log_prefix_cr},
};

static map<string, LOGLEVEL> mapstrll = {
        {"none", LOGLEVEL::L_NONE},
        {"trace", LOGLEVEL::L_TRACE},
        {"debug", LOGLEVEL::L_DEBUG},
        {"info", LOGLEVEL::L_INFO},
        {"warn", LOGLEVEL::L_WARNING},
        {"err", LOGLEVEL::L_ERROR},
        {"cr", LOGLEVEL::L_CRITICAL},
};


extern "C" BOOST_SYMBOL_EXPORT
bool TurnOnOffDebugOutput(const string & onoff, string & ret)
{
    std::set<string> optionset;
    string optiononoff;
    for (auto c : onoff) {
        if (c == ' ') {
            optionset.insert(optiononoff);
            optiononoff = "";
            continue;
        }
        auto ch = std::tolower(c);
        optiononoff.append(1, ch);
    }

    if(!optiononoff.empty())
        optionset.insert(optiononoff);

    for (auto& ll : mapstrll) {
        if (optionset.count(ll.first)) {
            floglevel = ll.second;
            optionset.erase(ll.first);
        }
    }

    for (auto& option : optionset) {
        if (option == "both") {
            fPrintToConsole = true;
            fPrintToDebugFile = true;
        }
        else if (option == "con") {
            fPrintToConsole = true;
            fPrintToDebugFile = false;
        }
        else if (option == "file") {
            fPrintToConsole = false;
            fPrintToDebugFile = true;
        }
        else if (option == "off") {
            fPrintToConsole = false;
            fPrintToDebugFile = false;
        }
        else if (option == "nobt") {
            fPrintBacktracking = false;
            fPrintBacktracking_node = false;
            strBacktracking_node = "";
        }
        else if (option == "bt") {
            fPrintBacktracking = true;
        }
        else if (option.find("bt:") != string::npos) {
            fPrintBacktracking_node = true;
            strBacktracking_node = option.substr(3);
        }
        else if (option == "cp") {
            fPrintCostParse = true;
        }
        else if (option == "nocp") {
            fPrintCostParse = false;
        }
        else if (option == "nogrep") {
            fPrintgrep = false;
            vecgreps.clear();
        }
        else if (option.find("grep:") != string::npos) {
            fPrintgrep = true;
            string opt = option.substr(5);

            bool bfind = false;
            for (auto& str : vecgreps) {
                if (str == opt) {
                    bfind = true;
                    break;
                }
            }

            if(!bfind)
                vecgreps.push_back(opt);
        }
    }

    //HCE: show
    if (fPrintToConsole && fPrintToDebugFile) {
        optiononoff = "both";
    }
    else if (!fPrintToConsole && !fPrintToDebugFile) {
        optiononoff = "off";
    }
    else if (fPrintToConsole && !fPrintToDebugFile) {
        optiononoff = "con";
    }
    else if (!fPrintToConsole && fPrintToDebugFile) {
        optiononoff = "file";
    }

    if (fPrintCostParse) {
        optiononoff += "(costparsing)";
    }

    if (fPrintBacktracking) {
        optiononoff += "(backtracking)";
    }
    else if (fPrintBacktracking_node) {
        optiononoff += "(backtracking from node: ";
        optiononoff += strBacktracking_node;
        optiononoff += ")";
    }

    string strgreps;
    for (auto& str : vecgreps) {
        strgreps += (str + " ");
    }

    ret = strprintf("%s's debug settings: '%s' (log level: %s) (output grep: %d %s)",
        mdname,
        optiononoff.c_str(), mapll[floglevel].c_str(),
        fPrintgrep, strgreps.c_str() );

    if (optionset.size() == 0) {
        ret += strprintf("\nUsage: debug %s [option...]\n"
            "\tOutput target : con/file/both/off\n "
            "\tLog level: cr/err/warn/info/debug/trace\n"
            "\tBack tracing: bt/bt:FROMNODEID/nobt\n"
            "\tCost parse: cp/nocp\n"
            "\tFilter: grep:PATTERN/nogrep\n",
            mdname);
    }

    return true;
}


