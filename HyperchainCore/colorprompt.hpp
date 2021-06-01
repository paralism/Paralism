/*Copyright 2016-2021 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this?
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,?
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#include "linenoise-ng/linenoise.h"

#include <functional>

#include <boost/algorithm/string.hpp>

#define HCPROMPT "hc $"

static vector<string> _completionwords;

class CColorPrompt
{
public:
    enum PRCLR : char
    {
        RED = 31,
        GREEN = 32,
        YELLOW = 33,
        BLUE = 34,
        MAGENTA = 35,
        CYAN = 36,
        WHITE = 37,
        cEND,
    };

public:
    CColorPrompt(bool daemonmode, const string &pmpttxt= HCPROMPT, const string& hisfile="") :
        _daemon(daemonmode),
        _prompttxt(pmpttxt),
        _hisfile(hisfile)
    {
        if (!_daemon && !_hisfile.empty()) {
            linenoiseInstallWindowChangeHandler();

            linenoiseHistorySetMaxLen(200);
            char *linesettings = nullptr;
            linenoiseHistoryLoad(_hisfile.c_str(), &linesettings);

            if (linesettings == nullptr) {
                promptcolor("GREEN");
            }
            else {
                promptcolor(linesettings);
                free(linesettings);
            }

            linenoiseSetCompletionCallback(CColorPrompt::completionHook);
        }
    }

    ~CColorPrompt()
    {
        if (!_daemon && !_hisfile.empty()) {
            linenoiseHistorySave(_hisfile.c_str(), _clr.c_str());
            linenoiseHistoryFree();
        }
    }

    string getinputline()
    {
        string command;
        if (!_daemon) {
            char* result = linenoise(_prompt.c_str());
            if (!result) {
                //maybe CTRL - C
                return "";
            }
            command = result;
            free(result);
        }
        else {
            getline(std::istream(cin.rdbuf()), command);
        }
        return command;
    }

    void addhisline(const string& commd)
    {
        if (!_daemon) {
            linenoiseHistoryAdd(commd.c_str());
        }
    }

    void clearhistories()
    {
        linenoiseHistoryFree();

        if (!_daemon && !_hisfile.empty()) {
            linenoiseHistorySave(_hisfile.c_str(), _clr.c_str());
        }
    }

    void promptcolor(const string command)
    {
        auto s = command;
        boost::algorithm::trim(s);

        if (s.empty()) {
            s = "GREEN";
        }

        if (!_mapclr.count(s)) {
            return;
        }

        _prompt = StringFormat("\x1b[1;%dm%s\x1b[0m ", _mapclr[s], _prompttxt);
        _clr = s;
    }

    string gethistories()
    {

        if (_daemon) {
            return "";
        }

        ostringstream oss;
        for (int index = 1; ; ++index) {
            char* hist = linenoiseHistoryLine(index);
            if (hist == NULL) break;
            oss << StringFormat("%4d: %s\n", index, hist);
            free(hist);
        }
        return oss.str();
    }

    void setcompletewords(const vector<string> &words)
    {
        _completionwords = words;
    }

private:

    static void completionHook(char const* prefix, linenoiseCompletions* lc)
    {
        size_t i;

        static const char* words_builtin[] = {
            "RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "WHITE",
            "add", "addmodule",
            "both", "call",
            "debug", "trace", "critical", "ginfo", "sfee",
            "exit", "help", "sendfrom", "sendtoaddr", "test",
            "ledger", "paracoin", "start", "stop", "simulate",
            "WIF", "WIFC", "ikpf", "ekpf", "sacc",
            "wpass" , "chwpass", NULL
        };

        for (i = 0; words_builtin[i] != NULL; ++i) {
            if (strncmp(prefix, words_builtin[i], strlen(prefix)) == 0) {
                linenoiseAddCompletion(lc, words_builtin[i]);
            }
        }

        for (auto &word : _completionwords) {
            if (strncmp(prefix, word.c_str(), strlen(prefix)) == 0) {
                linenoiseAddCompletion(lc, word.c_str());
            }
        }

    }

private:
    bool _daemon = false;
    string _hisfile;

    string _prompttxt;
    string _prompt;
    string _clr = "GREEN";

    map<string, PRCLR> _mapclr = {
        {"RED", RED},
        {"GREEN", GREEN},
        {"YELLOW", YELLOW},
        {"BLUE", BLUE},
        {"MAGENTA", MAGENTA},
        {"CYAN", CYAN},
        {"WHITE", WHITE},
    };
};