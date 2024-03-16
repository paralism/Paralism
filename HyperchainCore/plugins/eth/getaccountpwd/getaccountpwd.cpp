/*Copyright 2016-2023 hyperchain.net (Hyperchain)

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


#include <iostream>
#include <cstdlib>
#include <fstream>
#include <stdio.h>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/process.hpp>

#if defined(_WIN32)
#include <windows.h>
#else
#include <termios.h>
#endif


#include <string>


#include "libdevcore/Exceptions.h"

using namespace std;
using namespace dev;
namespace bi = boost::interprocess;


string getPwd(string _prompt)
{
#if defined(_WIN32)
    cout << _prompt << flush;
    // Get current Console input flags
    HANDLE hStdin;
    DWORD fdwSaveOldMode;
    if ((hStdin = GetStdHandle(STD_INPUT_HANDLE)) == INVALID_HANDLE_VALUE)
        BOOST_THROW_EXCEPTION(
            ExternalFunctionFailure() << errinfo_externalFunction("GetStdHandle"));
    if (!GetConsoleMode(hStdin, &fdwSaveOldMode))
        BOOST_THROW_EXCEPTION(
            ExternalFunctionFailure() << errinfo_externalFunction("GetConsoleMode"));
    // Set console flags to no echo
    if (!SetConsoleMode(hStdin, fdwSaveOldMode & (~ENABLE_ECHO_INPUT)))
        BOOST_THROW_EXCEPTION(
            ExternalFunctionFailure() << errinfo_externalFunction("SetConsoleMode"));
    // Read the string
    std::string ret;
    std::getline(cin, ret);
    // Restore old input mode
    if (!SetConsoleMode(hStdin, fdwSaveOldMode))
        BOOST_THROW_EXCEPTION(
            ExternalFunctionFailure() << errinfo_externalFunction("SetConsoleMode"));
    return ret;
#else
    struct termios oflags;
    struct termios nflags;
    char password[256];

    // disable echo in the terminal
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0)
        BOOST_THROW_EXCEPTION(ExternalFunctionFailure() << errinfo_externalFunction("tcsetattr"));

    printf("%s", _prompt.c_str());
    if (!fgets(password, sizeof(password), stdin))
        BOOST_THROW_EXCEPTION(ExternalFunctionFailure() << errinfo_externalFunction("fgets"));
    password[strlen(password) - 1] = 0;

    // restore terminal
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0)
        BOOST_THROW_EXCEPTION(ExternalFunctionFailure() << errinfo_externalFunction("tcsetattr"));


    return password;
#endif

}

int main(int argc, char* argv[]) 
{
    //HC: 获取账户密码
    if (argc < 3) {
        cerr << "[getaccountpwd] invalid parameters\n";
        return -1;
    }

    //HC: Use as code debug
    //std::this_thread::sleep_for(chrono::seconds(20));

    string shmname = argv[1];
    string _prompt = argv[2];

    try {
        bi::shared_memory_object shm(bi::open_only, shmname.c_str(), bi::read_write);

        //HC: 映射共享内存
        bi::mapped_region region(shm, bi::read_write);
    
        string pwd = getPwd(_prompt);
        size_t s = pwd.size();
        if (s > 256) {
            s = 256;
        }
        std::memcpy(region.get_address(), pwd.c_str(), pwd.size());
    }
    catch (std::exception &e) {
        cerr << "[getaccountpwd] Exception occurred: " << e.what() << endl;
    }

    return 0;
}
