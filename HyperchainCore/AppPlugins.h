#pragma once

#include "plugins/PluginContext.h"
#include "node/ObjectFactory.hpp"

#include <boost/function.hpp>
#include <boost/dll/shared_library.hpp>


#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <iomanip>
using namespace std;


using MAPARGS = std::map<std::string, std::string>;
using MAPMULTIARGS = std::map<std::string, std::vector<std::string>>;

extern MAPARGS mapHCArgs;
extern MAPMULTIARGS mapHCMultiArgs;
extern std::vector<std::string> vHCCommands;

class AppPlugins
{
public:
    AppPlugins(int argc, char *argv[]) : _argc(argc), _argv(argv)
    {
        Init();
    }

    ~AppPlugins() {}

    void AddApplication(const string& appname);

    string GetGenesisBlock(const string& appname, string& payload)
    {
        bool isNeedUnloaded = false;
        if (!_mapAppFunc.count(appname)) {
            AddApplication(appname);
            isNeedUnloaded = true;
        }

        if (!_mapAppFunc.count(appname)) {
            return "";
        }

        auto& f = _mapAppFunc[appname];
        string hashmtroot = f.appGetGenesisBlock(payload);

        if (isNeedUnloaded) {
            StopApp(appname);
        }

        return hashmtroot;
    }

    template<class InputIt>
    void StartApp(const string& appname, InputIt first, InputIt last)
    {
        if (_mapAppFunc.count(appname)) {
            auto & f = _mapAppFunc[appname];
            if (f.appIsStopped()) {
                StopApp(appname);
            }
            else {
                std::cout << "Module " << appname << " has already run" << endl;
                return;
            }
        }

        if (!_mapAppFunc.count(appname)) {
            AddApplication(appname);
        }

        if (_mapAppFunc.count(appname)) {
            auto & f = _mapAppFunc[appname];

            while (first != last) {
                //HC: must begin with '-'
                if ((*first)[0] != '-') {
                    string param = *first;
                    param.insert(0, "-");
                    f.appargv.push_back(param);
                }
                else {
                    f.appargv.push_back(*first);
                }
               ++first;
            }

            StartApp(appname);
        }
    }

    void StartApp(const string& appname);
    void StopApp(const string& appname, bool isErase = true);
    void StartAllApp();
    void StopAllApp();
    void GetAllAppStatus(map<string, string>& mapappstatus);
    void RegisterAllAppTasks(void* objFactory);

    typedef struct _appfunc {

        std::list<string> appargv;
        boost::dll::shared_library applib;

        boost::function<void(string&)> appInfo;
        boost::function<void(int&,string&)> appRunningArg;
        boost::function<bool(PluginContext*)> appStart;
        boost::function<bool()> appIsStopped;
        boost::function<void()> appStop;
        boost::function<bool(void* objFa)> appRegisterTask;
        boost::function<void(void* objFa)> appUnregisterTask;
        boost::function<bool(int, string&)> appResolveHeight;
        boost::function<bool(const string&, string&)> appResolvePayload;
        boost::function<bool(const string&, string&)> appTurnOnOffDebugOutput;
        boost::function<string(string& payload)> appGetGenesisBlock;

        boost::function<bool(const list<string>&, string&, string&)> appConsoleCmd;

        bool load(const string& appname);
        void unload();

    } APPFUNC;

    APPFUNC* operator [](const string& appname) {
        if (_mapAppFunc.count(appname)) {
            return &(_mapAppFunc[appname]);
        }
        return nullptr;
    }

    typedef unordered_map<string, APPFUNC>::iterator iterator;
    typedef unordered_map<string, APPFUNC>::const_iterator const_iterator;
    iterator begin() { return _mapAppFunc.begin(); }
    iterator end() { return _mapAppFunc.end(); }
    const_iterator begin() const { return _mapAppFunc.begin(); }
    const_iterator end() const { return _mapAppFunc.end(); }

private:

    void Init();

private:
    int _argc;
    char** _argv;          //HC: 所有应用公用的参数


    unordered_map<string, APPFUNC> _mapAppFunc;
};

extern AppPlugins* g_appPlugin;
