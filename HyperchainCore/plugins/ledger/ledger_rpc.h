/*Copyright 2016-2022 hyperchain.net (Hyperchain)

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
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "protocol_rpc.h"
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

using namespace json_spirit;


void ThreadRPCServer(void* parg);
int CommandLineRPC(int argc, char *argv[]);

template<typename T>
void ConvertTo(Value& value)
{
    if (value.type() == str_type)
    {
        // reinterpret string as unquoted json value
        Value value2;
        if (!read_string(value.get_str(), value2))
            throw runtime_error("type mismatch");
        value = value2.get_value<T>();
    }
    else
    {
        value = value.get_value<T>();
    }
}


Value issuetoken(const Array& params, bool fHelp);
Value importtoken(const Array& params, bool fHelp);
Value listaccounts(const Array& params, bool fHelp);
Value getaddressesbyaccount(const Array& params, bool fHelp);

Value sendfrom(const Array& params, bool fHelp);
Value sendtoaddress(const Array& params, bool fHelp);

Value setgenerate(const Array& params, bool fHelp);

Value gettransaction(const Array& params, bool fHelp);
Value listtransactions(const Array& params, bool fHelp);
Value gettransaction(const Array& params, bool fHelp);

Value encryptwallet(const Array& params, bool fHelp);
Value walletpassphrase(const Array& params, bool fHelp);
Value walletpassphrasechange(const Array& params, bool fHelp);

Value setaccount(const Array& params, bool fHelp);
Value settxfee(const Array& params, bool fHelp);

Value getinfo(const Array& params, bool fHelp);

