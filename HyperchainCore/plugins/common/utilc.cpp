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
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"
#include "utilc.h"

#include <iostream>
using namespace std;


void CommadLineProgress::Update(double newProgress)
{
    currentProgress += newProgress;
    amountOfFiller = (int)((currentProgress / neededProgress) * (double)pBarLength);
}

void CommadLineProgress::PrintPercent()
{
    currUpdateVal %= pBarUpdater.length();
    std::cout << "\r" //Bring cursor to start of line
        << firstPartOfpBar;
    for (int a = 0; a < amountOfFiller; a++) { //Print out current progress
        std::cout << pBarFiller;
    }
    std::cout << pBarUpdater[currUpdateVal];
    for (int b = 0; b < pBarLength - amountOfFiller; b++) { //Print out spaces
        std::cout << " ";
    }
    std::cout << lastPartOfpBar //Print out last part of progress bar
        << " (" << (int)(100 * (currentProgress / neededProgress)) << "%)" //This just prints out the percent
        << flush;
    currUpdateVal += 1;
}

void CommadLineProgress::Start()
{
    _spentt.Reset();
    _ncount = 0;
    PrintStatus(0, "starting...");
}

//
void CommadLineProgress::PrintStatus(uint32_t nAddCount, const string& msg)
{
    //[ 145668   176(s)   18776(n/s) ] (msg)
    cout << "\r"             //Bring cursor to start of line
        << firstPartOfpBar;
    _ncount += nAddCount;

    uint64_t ms = _spentt.Elapse();
    if (ms == 0) {
        ms = 1; //1ms
    }
    cout << strprintf(" %d   %u(s)   %u(n/s) %s   ( %s )",
                _ncount, ms / 1000, _ncount * 1000 / ms,
                lastPartOfpBar.c_str(), msg.c_str()) << flush;
}


