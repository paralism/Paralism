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

#pragma once

#include <chrono>
#include <string>

 class CSpentTime
{
public:
    CSpentTime();
    uint64_t Elapse();
    void Reset();
private:
    std::chrono::system_clock::time_point  _StartTimePoint;
};


class CommadLineProgress
{
public:
    //Way 1:
    void Update(double newProgress);
    void PrintPercent();

    //Way 2:
    void Start();
    void PrintStatus(uint32_t nAddCount, const std::string& msg = "");


private:
    std::string firstPartOfpBar = "[", //Change these at will (that is why I made them public)
        lastPartOfpBar = "]",
        pBarFiller = "|",
        pBarUpdater = "/-\\|";

    int amountOfFiller,
        pBarLength = 50,        //I would recommend NOT changing this
        currUpdateVal = 0;      //Do not change
    double currentProgress = 0, //Do not change
        neededProgress = 100;   //I would recommend NOT changing this

    CSpentTime _spentt;
    uint64_t _ncount;
};


