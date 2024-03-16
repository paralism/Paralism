#pragma once

#include <string>
#include <vector>

template<class Container>
std::string ToHexString(const Container& container)
{
    std::string rs;
    rs.resize(container.size() * 2);

    char* p = &rs[0];
    for (unsigned char c : container) {
        sprintf(p, "%02x", c);
        p += 2;
    }
    return rs;
}

template<int N>
std::string ToHexString(unsigned char *data)
{
    std::vector<unsigned char> container(data, data + N);
    return ToHexString(container);
}
