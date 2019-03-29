﻿/*Copyright 2016-2019 hyperchain.net (Hyperchain)

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

#ifndef HttpUnitH
#define HttpUnitH

#include <string>


using namespace std;

void UseSwitchInHttpDownload(bool bUse = true);

int HttpDownload(string URL,char **body,unsigned int &recvLen, const string& post="",const string& AdditionHead="", bool IsHead=false, string aToken="", bool bOnce = false, int timeout = 4);
int HttpDownloadT(string URL,char **body, unsigned int &recvLen, bool bOnce = false, int timeout = 4);

int HttpDownloadF(string URL, char **body, unsigned int &recvLen, bool bOnce = false, int timeout = 4);
int HttpDownloadFile(string URL, char **body, unsigned int &recvLen, const string& post = "", const string& AdditionHead = "", bool IsHead = false, string aToken = "", bool bOnce = false, int timeout = 4);

#endif