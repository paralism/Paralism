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

#include "headers/shastruct.h"


class BLOCKTRIPLEADDRESS
{
public:
    uint32 hid = 0;            //HC: hyper block id
    uint16 chainnum = 0;
    uint16 id = 0;
    T_SHA256 hhash;             //HC: hyper block hash

public:
    BLOCKTRIPLEADDRESS() {}

    BLOCKTRIPLEADDRESS(const T_LOCALBLOCKADDRESS& addr)
    {
        hid = addr.hid;
        chainnum = addr.chainnum;
        id = addr.id;
    }

    BLOCKTRIPLEADDRESS(const BLOCKTRIPLEADDRESS& addr)
    {
        hid = addr.hid;
        chainnum = addr.chainnum;
        id = addr.id;
        hhash = addr.hhash;
    }

    bool isValid() const
    {
        return id > (uint16)0 && id < 10000 &&
            chainnum >(uint16)0 && chainnum < 5000 && hhash > 0;
    }

    bool operator <(const BLOCKTRIPLEADDRESS& addr) const
    {
        if (hid < addr.hid) {
            return true;
        } else if (hid > addr.hid) {
            return false;
        }

        if (chainnum < addr.chainnum) {
            return true;
        } else if (chainnum > addr.chainnum) {
            return false;
        }

        if (id < addr.id) {
            return true;
        } else if (id > addr.id) {
            return false;
        }
        return hhash < addr.hhash;
    }

    bool operator >=(const BLOCKTRIPLEADDRESS& addr) const
    {
        return !(*this < addr);
    }

    friend bool operator==(const BLOCKTRIPLEADDRESS& a, const BLOCKTRIPLEADDRESS& b)
    {
        return a.hid == b.hid && a.chainnum == b.chainnum && a.id == b.id && a.hhash == b.hhash;
    }

    friend bool operator!=(const BLOCKTRIPLEADDRESS& a, const BLOCKTRIPLEADDRESS& b)
    {
        return !(a == b);
    }

    //string ToString() const
    //{
    //    return strprintf("[%d,%d,%d(%s)]", hid, chainnum, id, hhash.ToPreViewString().c_str());
    //}
};
