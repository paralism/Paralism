/*Copyright 2016-2022 hyperchain.net (Hyperchain)

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
#pragma once

#include <iostream>

#pragma pack(1)
typedef struct ntpheader {
    uint8_t _flags;//Flags
    uint8_t _pcs;//Peer Clock Stratum
    uint8_t _ppt;//Peer Polling Interval
    uint8_t _pcp;//Peer Clock Precision
    uint32_t _rdy;//Root Delay
    uint32_t _rdn;//Root Dispersion
    uint32_t _rid;//Reference ID
    uint64_t _ret;//Reference Timestamp
    uint64_t _ort;//Origin Timestamp
    uint64_t _rct;//Receive Timestamp
    uint64_t _trt;//Transmit Timestamp
}NtpHeader;
#pragma pack()

class NtpPacket {
public:
    NtpPacket() {
        _rep._flags = 0xdb;
        //    11.. ....    Leap Indicator: unknown
        //    ..01 1...    NTP Version 3
        //    .... .011    Mode: client
        _rep._pcs = 0x00;//unspecified
        _rep._ppt = 0x01;
        _rep._pcp = 0x01;
        _rep._rdy = 0x01000000;//big-endian
        _rep._rdn = 0x01000000;
        _rep._rid = 0x00000000;
        _rep._ret = 0x0;
        _rep._ort = 0x0;
        _rep._rct = 0x0;
        _rep._trt = 0x0;
    }

    friend std::ostream& operator<<(std::ostream& os, const NtpPacket& ntpacket) {
        return os.write(reinterpret_cast<const char*>(&ntpacket._rep), sizeof(ntpacket._rep));
    }

    friend std::istream& operator>>(std::istream& is, NtpPacket& ntpacket) {
        return is.read(reinterpret_cast<char*>(&ntpacket._rep), sizeof(ntpacket._rep));
    }

public:
    NtpHeader _rep;
};

class NtpClient {
public:
    NtpClient(const std::string& serverIp)
        :_serverIp(serverIp) {
    }

    time_t getTime();
    void show(time_t tt);

private:
    const uint16_t NTP_PORT = 123;
    std::string _serverIp;
};