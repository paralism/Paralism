/*Copyright 2016-2024 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

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

#include "common.h"

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <codecvt>

#endif

string t2s(const utility::string_t& ts)
{
#ifdef WIN32
    // On Windows, utility::string_t are wide, and Chinese is UCS2 code
    //wstring_convert<std::codecvt<wchar_t, char, std::mbstate_t>> strCnv;
    //return strCnv.to_bytes(ts); //HC here throw exception(bad conversion) for Chinese

    //HC: UCS2 to UTF-8
    try {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.to_bytes(ts);
    }
    catch (const std::exception& e) {
        cerr << "t2s happens exception: " << e.what() << endl;
    }
    return "";

#else
    // On POSIX platforms, utility::string_t are narrow, and Chinese is UTF-8 code
    return string(ts);
#endif
}

utility::string_t s2t(const std::string& s)
{
#ifdef WIN32
    // On Windows, all strings are wide
    //std::wstring_convert<std::codecvt<wchar_t, char, std::mbstate_t>> strCnv;
    //return strCnv.from_bytes(s);

    try {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.from_bytes(s);
    }
    catch (const std::exception& e) {
        cerr << "s2t happens exception: " << e.what() << " when convert " << s << endl;
    }
    return utility::string_t();
#else
    // On POSIX platforms, all strings are narrow
    return utility::string_t(s);
#endif
}

//HC: char to wchar_t, ignore any encoding format
utility::string_t s2t_ign(const std::string& s)
{
#ifdef WIN32
    // On Windows, all strings are wide
    std::wstring_convert<std::codecvt<wchar_t, char, std::mbstate_t>> strCnv;
    return strCnv.from_bytes(s);

#else
    // On POSIX platforms, all strings are narrow
    return utility::string_t(s);
#endif
}

void stringTostringlist(const string& str, list<string>& l, char delimiter)
{
    string piece;
    string tmp = str;

    size_t len = tmp.size();

    std::size_t found = tmp.find_first_of(delimiter);
    while (found < len) {
        piece = tmp.substr(0, found);
        l.push_back(piece);

        size_t pos = tmp.find_first_not_of(delimiter, found);
        if (pos > found + 1) {
            tmp.erase(0, pos);
        }
        else {
            tmp.erase(0, found + 1);
        }
        found = tmp.find_first_of(delimiter);
    }

    if (tmp.size() > 0) {
        l.push_back(tmp);
    }
}


