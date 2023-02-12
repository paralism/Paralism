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

#include "../PluginContext.h"

extern "C" BOOST_SYMBOL_EXPORT bool StartApplication(PluginContext * context);
extern "C" BOOST_SYMBOL_EXPORT void StopApplication();
extern "C" BOOST_SYMBOL_EXPORT bool IsStopped();
extern "C" BOOST_SYMBOL_EXPORT void AppInfo(string&);
extern "C" BOOST_SYMBOL_EXPORT void AppRunningArg(int&, string&);
extern "C" BOOST_SYMBOL_EXPORT bool ResolveHeight(int, string&);
extern "C" BOOST_SYMBOL_EXPORT bool ResolvePayload(const string&, string&);

extern "C" BOOST_SYMBOL_EXPORT bool ConsoleCmd(const list<string> &cmdlist, string & info, string & savingcommand);
extern "C" BOOST_SYMBOL_EXPORT bool RegisterTask(void* objFac);

extern "C" BOOST_SYMBOL_EXPORT void UnregisterTask(void* objFac);



void issuecoin();

bool PutChainCb();

