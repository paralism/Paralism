// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2014-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

#include "CommonIO.h"
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/process.hpp>
#include <boost/process/extend.hpp>
#include <boost/dll.hpp>

#include <libdevcore/FileSystem.h>
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <stdio.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <termios.h>
#endif
#include "Exceptions.h"
#include <boost/filesystem.hpp>



using namespace std;
using namespace dev;

namespace fs = boost::filesystem;

namespace dev
{
namespace
{
void createDirectoryIfNotExistent(boost::filesystem::path const& _path)
{
    if (!fs::exists(_path))
    {
        fs::create_directories(_path);
        DEV_IGNORE_EXCEPTIONS(fs::permissions(_path, fs::owner_all));
    }
}

}  // namespace

string memDump(bytes const& _bytes, unsigned _width, bool _html)
{
    stringstream ret;
    if (_html)
        ret << "<pre style=\"font-family: Monospace,Lucida Console,Courier,Courier New,sans-serif; font-size: small\">";
    for (unsigned i = 0; i < _bytes.size(); i += _width)
    {
        ret << hex << setw(4) << setfill('0') << i << " ";
        for (unsigned j = i; j < i + _width; ++j)
            if (j < _bytes.size())
                if (_bytes[j] >= 32 && _bytes[j] < 127)
                    if ((char)_bytes[j] == '<' && _html)
                        ret << "&lt;";
                    else if ((char)_bytes[j] == '&' && _html)
                        ret << "&amp;";
                    else
                        ret << (char)_bytes[j];
                else
                    ret << '?';
            else
                ret << ' ';
        ret << " ";
        for (unsigned j = i; j < i + _width && j < _bytes.size(); ++j)
            ret << setfill('0') << setw(2) << hex << (unsigned)_bytes[j] << " ";
        ret << "\n";
    }
    if (_html)
        ret << "</pre>";
    return ret.str();
}

template <typename _T>
inline _T contentsGeneric(boost::filesystem::path const& _file)
{
    _T ret;
    size_t const c_elementSize = sizeof(typename _T::value_type);
    boost::filesystem::ifstream is(_file, std::ifstream::binary);
    if (!is)
        return ret;

    // get length of file:
    is.seekg(0, is.end);
    streamoff length = is.tellg();
    if (length == 0)
        return ret; // do not read empty file (MSVC does not like it)
    is.seekg(0, is.beg);

    ret.resize((length + c_elementSize - 1) / c_elementSize);
    is.read(const_cast<char*>(reinterpret_cast<char const*>(ret.data())), length);
    return ret;
}

bytes contents(boost::filesystem::path const& _file)
{
    return contentsGeneric<bytes>(_file);
}

bytesSec contentsSec(boost::filesystem::path const& _file)
{
    bytes b = contentsGeneric<bytes>(_file);
    bytesSec ret(b);
    bytesRef(&b).cleanse();
    return ret;
}

string contentsString(boost::filesystem::path const& _file)
{
    return contentsGeneric<string>(_file);
}

void writeFile(boost::filesystem::path const& _file, bytesConstRef _data, bool _writeDeleteRename)
{
    if (_writeDeleteRename)
    {
        fs::path tempPath = appendToFilename(_file, "-%%%%%%"); // XXX should not convert to string for this
        writeFile(tempPath, _data, false);
        // will delete _file if it exists
        fs::rename(tempPath, _file);
    }
    else
    {
        createDirectoryIfNotExistent(_file.parent_path());

        boost::filesystem::ofstream s(_file, ios::trunc | ios::binary);
        s.write(reinterpret_cast<char const*>(_data.data()), _data.size());
        if (!s)
            BOOST_THROW_EXCEPTION(FileError() << errinfo_comment("Could not write to file: " + _file.string()));
        DEV_IGNORE_EXCEPTIONS(fs::permissions(_file, fs::owner_read | fs::owner_write));
    }
}

void copyDirectory(boost::filesystem::path const& _srcDir, boost::filesystem::path const& _dstDir)
{
    createDirectoryIfNotExistent(_dstDir);

    for (fs::directory_iterator file(_srcDir); file != fs::directory_iterator(); ++file)
        fs::copy_file(file->path(), _dstDir / file->path().filename());
}

std::tuple<int, std::string> startProcess(const std::string& processName, const std::vector<std::string>& args)
{
    namespace bp = ::boost::process;

    int pid = -1;
    std::string err;

    try {
#if defined(_WIN32)
        auto p = processName + ".exe";
#else 
        auto p = processName;
#endif
        if (!boost::filesystem::exists(p)) {
            p = boost::dll::program_location().parent_path().string() + "/" + p;
            if (!boost::filesystem::exists(p))
            {
                err = p + " not exist";
                return std::make_tuple(pid, err);
            }
        }
        auto env{ ::boost::this_process::environment() };
        bp::child c(
            p, env, bp::args(args)
#if defined(_WIN32)
            , boost::process::extend::on_setup = [](auto& exec) {
                exec.creation_flags |= boost::winapi::CREATE_NEW_CONSOLE_;
            }
#endif 
        );

        pid = c.id();
        c.wait();
    }
    catch (boost::process::process_error& exc) {
        err = exc.what();
        pid = -1;
    }
    return std::make_tuple(pid, err);
} 

std::string getPassword(std::string const& _prompt)
{
    //HC: 因为主线程和子线程同时调用getline存在冲突，所以改成从另一个进程获取密码方式
    //HCE: Because there is a conflict when the main thread and the child thread call 'getline' at the same time, it is changed to obtain the password from another process.

#if !defined(_WIN32)
    //HC: Linux平台不支持输入，只能先解锁账户
    return "";
#endif

    namespace bi = boost::interprocess;
    namespace bp = ::boost::process;

    //HC：随机数
    std::random_device rd;
    std::mt19937 gen(rd());

    string sRand(8,'a');
    for (auto& i : sRand)
        i = (uint8_t)std::uniform_int_distribution<uint16_t>('a', 'z')(gen);

    string shmname = "aleth_sharememory" + sRand;
    struct shm_remove
    {
        shm_remove(string name) : _shmname(name) { bi::shared_memory_object::remove(_shmname.c_str()); }
        ~shm_remove() { bi::shared_memory_object::remove(_shmname.c_str()); }

        string _shmname;
    } remover(shmname);

    //Create a shared memory object.
    bi::shared_memory_object shm(bi::create_only, shmname.c_str(), bi::read_write);

    //Set size
    shm.truncate(1024);

    //Map the whole shared memory in this process
    bi::mapped_region region(shm, bi::read_write);

    //Write all the memory to 0
    std::memset(region.get_address(), 0, region.get_size());

    std::vector<std::string> args;
    args.push_back(shmname);
    args.push_back(_prompt);

    int pid = -1;
    std::string err;

    cout << "Requesting the account password...\n" << flush;

    std::string exec = "getaccountpwd";
    std::tie(pid, err) = startProcess(exec, args);
    if (pid == -1) {
        cerr << err << endl;
        return string("");
    }

    char* s = static_cast<char*>(region.get_address());
    return string(s);
}

}  // namespace dev
