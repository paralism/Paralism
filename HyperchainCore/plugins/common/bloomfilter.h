/*Copyright 2016-2021 hyperchain.net (Hyperchain)

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

#ifndef _BLOOMFILTER_
#define _BLOOMFILTER_

#include <math.h>
#include <vector>
#include <bitset>

#include <openssl/md5.h>

#include <bitset>
#include <memory>

class BloomFilter
{
public:
    BloomFilter();

    void insert(const std::string& object);
    void insert(const char* object, int len);

    void clear();

    bool contain(const char* object, int len) const;
    bool contain(const std::string& object) const;

    size_t object_count() const;

    bool empty() const;

    BloomFilter& operator =(const BloomFilter& bf);
    BloomFilter& operator |(const BloomFilter& bf);

private:

    void hashtable_init();
    void md5hash(const std::string& val) const
    {
        const unsigned char* const md5_input_val = reinterpret_cast<const unsigned char*>(val.data());
        const size_t md5_input_length = val.length();
        MD5(md5_input_val, md5_input_length, _md5_hash_result);
    }


private:
    // Size of the MD5 hash result, always fixed to 16 bytes.
    static constexpr size_t _md5_result_size_bytes = 16;

    // Size of the bloom filter state in bits (2^24).
    static constexpr size_t _bloomfilter_store_size = 0xffffff + 1; //16,777,216, +1 avoid bitset overflow

    using bit_pool = std::bitset<_bloomfilter_store_size>;

    std::bitset<256 + 1> _md5_store_front;
    std::shared_ptr<bit_pool> _sp_md5_store;

    size_t _object_count;

    //const std::unique_ptr<unsigned char[]> _md5_hash_result;
    mutable unsigned char _md5_hash_result[_md5_result_size_bytes];

    std::vector<unsigned int (*)(const char*, size_t len)> _hashfunctable;

    std::vector<bit_pool> _vec_bit_pool;

};



#endif
