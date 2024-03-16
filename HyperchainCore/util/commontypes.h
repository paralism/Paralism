#ifndef COMMONTYPES_H
#define COMMONTYPES_H

//HC: Notice: Value of type should be continuous
#define HC_ENUM_HELP(classname, enumtype, ...) \
namespace {\
    enum class classname : enumtype { __VA_ARGS__ }; \
    inline const std::vector<std::string>& classname##ValueNameList() { \
        static std::vector<std::string> res; \
        if (res.empty()) { \
            std::stringstream ss(#__VA_ARGS__); \
            std::string item; \
            while (std::getline(ss, item, ',')) { \
                res.push_back(item); \
            } \
        } \
        return res; \
    } \
    inline const std::string& classname##ValueName(classname t) { \
        return classname##ValueNameList()[static_cast<int>(t)]; \
    } \
    inline std::ostream& operator<< (std::ostream& os, const classname& o) { \
        os << classname##ValueName(o); \
        return os; \
    } \
    inline classname& operator++(classname& o) {o = static_cast<classname>(static_cast<int>(o) + 1); return o; };\
    inline classname operator++(classname& o, int) { auto old = o; ++o; return old; }; \
    \
    template<typename Fn> \
    inline void classname##ForEach(Fn fn) { \
         for (classname i = std::numeric_limits<classname>::min(); i < classname::LAST; ++i) { \
            fn(i); \
         } \
    } \
}

#define HC_ENUM(classname, enumtype, ...) \
    HC_ENUM_HELP(classname, enumtype, __VA_ARGS__, LAST)


#endif
