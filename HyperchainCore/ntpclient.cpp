/*Copyright 2016-2024 hyperchain.net (Hyperchain)

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

#ifdef _WIN32
#include <WinSock2.h>
#endif

#include "ntpclient.h"
#include <boost/asio.hpp>
using namespace boost::asio;

const static uint64_t n1970_1900_Seconds = 2208988800;

static void reverseByteOrder(uint64_t& in) {
	uint64_t rs = 0;
	int len = sizeof(uint64_t);
	for (int i = 0; i < len; i++) {
		std::memset(reinterpret_cast<uint8_t*>(&rs) + len - 1 - i
			, static_cast<uint8_t> ((in & 0xFFLL << (i * 8)) >> i * 8)
			, 1);
	}
	in = rs;
}

#ifndef WIN32
uint64_t htonll(uint64_t val)
{
	if (1 == htonl(1))
		return val;
	return (((uint64_t)htonl(val)) << 32) + htonl(val >> 32);
}

uint64_t ntohll(uint64_t val)
{
	if (1 == htonl(1))
		return val;
	return (((uint64_t)ntohl(val)) << 32) + ntohl(val >> 32);
}
#endif

time_t NtpClient::getTime()
{
    io_service io;
    ip::udp::socket sock(io);

	ip::udp::endpoint ep(ip::address_v4::from_string(_serverIp), NTP_PORT);
	NtpPacket request;
	std::stringstream ss;
	std::string buf;
	ss << request;
	ss >> buf;
	sock.open(ip::udp::v4());

    std::array<uint8_t, 128> recvbuff;
    time_t tt = 0;
    sock.async_send_to(boost::asio::buffer(buf), ep, [&io, &ep, &sock, &tt, &recvbuff](const boost::system::error_code &ec, std::size_t bytes) {
        if (!ec) {
            sock.async_receive_from(buffer(recvbuff), ep, [&io, &sock, &recvbuff, &tt](const boost::system::error_code &ec, std::size_t bytes) {
                if (!ec) {
                    uint64_t last = 0;
                    NtpPacket resonpse;
                    std::stringstream rss;
                    rss.write(reinterpret_cast<const char*>(recvbuff.data()), bytes);
                    rss >> resonpse;

                    last = htonll(resonpse._rep._trt);
                    tt = (last >> 32) - n1970_1900_Seconds;

                    sock.close();
                    io.stop();
                }
            });
        }
    });

    //HC: 设置超时  
    boost::asio::deadline_timer send_timer(io);
    send_timer.expires_from_now(boost::posix_time::seconds(8)); //HC: 8秒超时  
    send_timer.async_wait([&](const boost::system::error_code& /*e*/) {
        if (!sock.is_open())
            return;
        std::cerr << "NtpClient operation timed out!" << std::endl;
        sock.close(); //HC: 关闭套接字以取消挂起的操作  
        });

    io.run();

    return tt;
}

void NtpClient::show(time_t tt)
{
	char strstamp[32] = { 0 };
	strftime(strstamp, 32, "%Y-%m-%d %H:%M:%S", std::localtime(&tt));

	std::cout << "Server:" << _serverIp.c_str() << '\t' << "Local Timestamp:" << time(0) << '\t' << "NTP Server:" << tt << "(" << /*to_simple_string(utc)*/strstamp << ")" << std::endl;
}
