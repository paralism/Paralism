/*Copyright 2016-2024 hyperchain.net (Hyperchain)

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

#pragma once

#include "headers/shastruct.h"
#include "node/Singleton.h"
#include <libdevcore/FixedHash.h>
#include <libdevcore/Guards.h>

using namespace dev;

class LatestHyperBlock {

public:
    static h256 toH256(const T_SHA256& thhash)
    {
        h256 h;
        for (unsigned i = 0; i < (unsigned)thhash.size(); ++i) {
            h[i] = *(thhash.data() + i);
        }
        return h;
    }

    static void Sync();
    static void CompareAndUpdate(uint32_t hid, const T_SHA256& thhash, bool isLatest);
    static uint32_t GetHID(h256* hhash = nullptr);

private:
    static uint32_t _hid;
    static h256 _hhash;
    static std::mutex _cs_latestHyperBlock;
};



