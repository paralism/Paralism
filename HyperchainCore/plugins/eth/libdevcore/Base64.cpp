/*
   base64.cpp and base64.h

   Copyright (C) 2004-2008 René Nyffenegger

   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   René Nyffenegger rene.nyffenegger@adp-gmbh.ch
*/
/// Adapted from code found on http://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
/// Originally by René Nyffenegger, modified by some other guy and then devified by Gav Wood.

#include "Base64.h"

using namespace dev;

static inline bool is_base64(byte c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

static inline byte find_base64_char_index(byte c)
{
    if ('A' <= c && c <= 'Z') return c - 'A';
    else if ('a' <= c && c <= 'z') return c - 'a' + 1 + find_base64_char_index('Z');
    else if ('0' <= c && c <= '9') return c - '0' + 1 + find_base64_char_index('z');
    else if (c == '+') return 1 + find_base64_char_index('9');
    else if (c == '/') return 1 + find_base64_char_index('+');
    else return 1 + find_base64_char_index('/');
}

std::string toBase64Encoding(bytesConstRef _in, char const* _base64_chars, bool _pad)
{
    std::string ret;
    int i = 0;
    int j = 0;
    byte char_array_3[3];
    byte char_array_4[4];

    auto buf = _in.data();
    auto bufLen = _in.size();

    while (bufLen--)
    {
        char_array_3[i++] = *(buf++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += _base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            ret += _base64_chars[char_array_4[j]];

        while (i++ < 3 && _pad)
            ret += '=';
    }

    return ret;
}

std::string dev::toBase64(bytesConstRef _in)
{
    static char const c_base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    bool const pad = true;
    return toBase64Encoding(_in, c_base64_chars, pad);
}

std::string dev::toBase64URLSafe(bytesConstRef _in)
{
    static char const c_base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";
    bool const pad = false;
    return toBase64Encoding(_in, c_base64_chars, pad);
}

bytes dev::fromBase64(std::string const& encoded_string)
{
    auto in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    byte char_array_3[3];
    byte char_array_4[4];
    bytes ret;

    while (in_len-- && encoded_string[in_] != '=' && is_base64(encoded_string[in_]))
    {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                char_array_4[i] = find_base64_char_index(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
        char_array_4[j] = find_base64_char_index(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++)
            ret.push_back(char_array_3[j]);
    }

    return ret;
}
