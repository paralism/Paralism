/*Copyright 2016-2021 hyperchain.net (Hyperchain)

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

#ifndef NETWORK_FUNCTIONS_H
#define NETWORK_FUNCTIONS_H

#include "Types.h"		// Needed for uint16 and uint32


/**
 * Parses a String-IP and saves the IP in the referenced variable.
 *
 * @param strIP A string-ip in the format "a.b.c.d".
 * @param Ip The value to save the result in.
 * @return True if the string was parsed, false otherwise.
 *
 * When parsing the IP address, whitespace before or after the
 * ip-address is ignored and the resulting IP is saved in
 * anti-host order.
 *
 * The reason for the existance of this function is the fact that
 * the standard inet_aton function treats numbers with 0 prefixed
 * as octals, which is desirable.
 *
 * Note: The reference value will not be changed unless the string
 *       contains a valid IP adress.
 */
bool StringIPtoUint32(const std::string &strIP, uint32& Ip);


/**
 * Parses a String-IP and returns the IP or 0 if it was invalid.
 *
 * @param strIP A string-ip in the format "a.b.c.d".
 * @return The resulting IP-address or zero if invalid (or 0.0.0.0).
 *
 * The IP will be saved in anti-host order.
 */
inline uint32 StringIPtoUint32(const std::string &strIP)
{
	uint32 ip = 0;
	StringIPtoUint32( strIP, ip );

	return ip;
}


/**
 * Checks for invalid IP-values.
 *
 * @param IP the IP-address to check.
 * @param filterLAN Specifies if LAN IP-ranges should be filtered.
 * @return True if it was valid, false otherwise.
 *
 * Note: IP must be in anti-host order (BE on LE platform, LE on BE platform).
 */
bool IsGoodIP( uint32 IP, bool filterLAN ) throw();


inline bool IsGoodIPPort(uint32 nIP, uint16 nPort) throw()
{
	return IsGoodIP(nIP, true) && nPort!=0;
}

#define HIGHEST_LOWID_ED2K_KAD		16777216


inline bool IsLowID(uint32 id)
{
	return (id < HIGHEST_LOWID_ED2K_KAD);
}


/**
 * Checks for LAN IPs.
 *
 * @param ip The IP-address to check.
 * @return True if it was a LAN IP, false otherwise.
 *
 * @note IP must be in anti-host order.
 */
bool IsLanIP(uint32_t ip) throw();

#endif // NETWORK_FUNCTIONS_H
// File_checked_for_headers
