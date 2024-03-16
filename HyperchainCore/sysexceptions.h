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

#include <boost/exception/exception.hpp>
#include <boost/exception/info.hpp>
#include <boost/exception/info_tuple.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/throw_exception.hpp>
#include <boost/tuple/tuple.hpp>
#include <exception>


#define VERSION_STRING "0.8.1 (build 228)"
#define UPDATE_STRING "http://www.hyperchain.net/test_renew/chenlx/win/paralism/"

void SoftwareInfo();
const char* GetUpdateUrl();

namespace hc
{
/// Base class for all exceptions.
struct Exception : virtual std::exception, virtual boost::exception
{
    const char* what() const noexcept override {
        return boost::diagnostic_information_what(*this);
    }
};

#define HC_SIMPLE_EXCEPTION(X) \
    struct X: Exception { \
    const char* what() const noexcept override { return #X; } \
    }

HC_SIMPLE_EXCEPTION(MissingHyperBlock);
HC_SIMPLE_EXCEPTION(FailedResolveBlock);
HC_SIMPLE_EXCEPTION(UnmatchedHashOfGenesisBlock);
HC_SIMPLE_EXCEPTION(TransactionVinPrevoutNotExists);


using errinfo_comment = boost::error_info<struct tag_comment, std::string>;

};

