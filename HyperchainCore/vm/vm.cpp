/*Copyright 2016-2022 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

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


#include "node/Singleton.h"
#include "HyperChain/HyperChainSpace.h"

#include "vm.h"

thread_local std::shared_ptr<qjs::Runtime> tls_VMRuntime(new qjs::Runtime());
thread_local std::shared_ptr<qjs::Context> tls_VMContext;
thread_local std::shared_ptr<qjs::Context> tls_VMContext_Exec;


namespace qjs {
    //HCE: Check condition 
    //HCE: @para ctx Pointer to JSContext
    //HCE: @para tripleaddr Triple address to locate the local block
    //HCE: @para localblkhash Local block hash
    //HCE: @para localblock Local block
    //HCE: @returns JS_NULL if success
    JSValue CheckCond(JSContext* ctx, const vector<int> tripleaddr, const std::string& localblkhash, T_LOCALBLOCK& localblock)
    {
        if (tripleaddr.size() != 3) {
            JS_ThrowReferenceError(ctx, "local block address error");
            return JS_EXCEPTION;
        }

        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

        T_LOCALBLOCKADDRESS addr;
        addr.set(tripleaddr[0], tripleaddr[1], tripleaddr[2]);

        if (!hyperchainspace->GetLocalBlock(addr, localblock)) {
            JS_ThrowReferenceError(ctx, "local block %s not exists", addr.tostring().c_str());
            return JS_EXCEPTION;
        }

        if (!localblock.GetAppType().isSmartContract()) {
            JS_ThrowReferenceError(ctx, "local block %s doesn't contain contract", addr.tostring().c_str());
            return JS_EXCEPTION;
        }

        //HCE: Check the hash
        if (!localblkhash.empty()) {
            if (localblkhash.size() != DEF_SHA256_LEN * 2) {
                JS_ThrowReferenceError(ctx, "invalid hash string, length must be 0 or %d", DEF_SHA256_LEN * 2);
                return JS_EXCEPTION;
            }
            T_SHA256 h = localblock.GetHashSelf();
            if (localblkhash != h.toHexString()) {
                JS_ThrowReferenceError(ctx, "block hash unmatched");
                return JS_EXCEPTION;
            }
        }

        return JS_NULL;
    }

    //HCE: Replace default module name(0e 63 6f 6d 70 69 6c 65 .compile) into newmodname
    //HCE: @para ctx Pointer to JSContext
    //HCE: @para script Script string
    //HCE: @para newmodname New module name
    //HCE: @returns JS_NULL if success
    JSValue RenameModuleName(JSContext* ctx, string& script, const string& newmodname)
    {
        qjs::Context qjsctx(JS_DupContext(ctx));
        string js_bytecode = qjsctx.dumpString(newmodname.c_str(), newmodname.size());
        string originstr = "\x0e\x63\x6f\x6d\x70\x69\x6c\x65";

        auto pos = script.find_first_of(originstr);
        if (pos == string::npos) {
            JS_ThrowInternalError(tls_VMContext_Exec->ctx, "Failed to specify module name: %s", newmodname.c_str());
            return JS_EXCEPTION;
        }
        script.replace(pos, originstr.size(), js_bytecode);
        return JS_NULL;
    }

    //HCE: import import_identifier as modulename from <Contract.%d.%d.%d>
    //HCE: For example: import * as sys from <Contract.1000.1.5>
    //HCE: The following mode don't supported:
    //HCE: import {class1, class2, function1, funtion2, var1, var2} from <Contract.1000.1.5>
    //HCE: @para ctx Pointer to JSContext
    //HCE: @para tripleaddr Triple address to locate the local block
    //HCE: @para localblkhash Local block hash
    //HCE: @para modulename Modulename to import
    //HCE: @returns JS_TRUE if success
    JSValue ImportContractEx(JSContext *ctx, vector<int> tripleaddr, const std::string& localblkhash, const string& modulename)
    {
        T_LOCALBLOCK localblock;
        if (JS_IsException(CheckCond(ctx, tripleaddr, localblkhash, localblock))) {
            return JS_EXCEPTION;
        }

        std::string script = localblock.GetScript();

        std::string strModuleFile = StringFormat("Contract.%d.%d.%d",
            tripleaddr[0], tripleaddr[1], tripleaddr[2]);

        if (JS_IsException(RenameModuleName(ctx, script, strModuleFile))) {
            return JS_EXCEPTION;
        }

        qjs::Context qjsctx(JS_DupContext(ctx));

        std::string_view jscode(script);
        qjsctx.evalBinary(jscode);

        //HCE: The following string must end with \0, and pass char* type into eval function
        std::string strScript = StringFormat("import * as %s from '%s'; globalThis.%s = %s;\n\0",
            modulename, strModuleFile, modulename, modulename);

        std::string strImpModule = StringFormat("<%s.imp>", strModuleFile);
        qjsctx.eval(strScript.c_str(), strImpModule.c_str(), JS_EVAL_TYPE_MODULE);

        return JS_TRUE;
    }

    //HCE: Call Contract in the block
    //HCE: @para ctx Pointer to JSContext
    //HCE: @para tripleaddr Triple address to locate the local block
    //HCE: @para localblkhash Local block hash
    //HCE: @returns JS_NewStringLen if success
    JSValue CallContract(JSContext* ctx, vector<int> tripleaddr, const std::string& localblkhash)
    {
        T_LOCALBLOCK localblock;
        if (JS_IsException(CheckCond(ctx, tripleaddr, localblkhash, localblock))) {
            return JS_EXCEPTION;
        }

        string value;
        std::string jscode(localblock.GetScript());

        JSRuntime* rt = JS_GetRuntime(ctx);
        std::shared_ptr<qjs::Context> tmpspctx;

        try {
            //HCE: Here use a temporary qjs::Context to avoid variable redeclaration conflict
            tmpspctx.reset(new qjs::Context(rt));
            VM::executeIsolated(tmpspctx, jscode, value);
        }
        catch (qjs::exception) {
            string excp_desc = tmpspctx->getExceptionDesc();

            JS_ThrowTypeError(ctx, excp_desc.c_str());
            return JS_EXCEPTION;
        }

        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    class contract
    {
    public:
        contract(const qjs::Value &v) : _v(v) {}

        //HCE: import a module from <Contract.%d.%d.%d>
        //HCE: @para tripleaddr Triple address to locate the local block
        //HCE: @para localblkhash Local block hash
        //HCE: @para modulename Modulename to import
        //HCE: @returns JS_TRUE if success
        JSValue importas(vector<int> tripleaddr, const std::string& localblkhash, const string& modulename)
        {
            return ImportContractEx(_v.ctx, tripleaddr, localblkhash, modulename);
        }

        //HCE: Call Contract in the block
        //HCE: @para tripleaddr Triple address to locate the local block
        //HCE: @para localblkhash Local block hash
        //HCE: @returns JS_NewStringLen if success
        JSValue call(vector<int> tripleaddr, const std::string& localblkhash)
        {
            return CallContract(_v.ctx, tripleaddr, localblkhash);
        }
    private:
        qjs::Value _v;
    };

    //HCE: constructor
    VM::VM()
    {
        if (!tls_VMContext) {
            tls_VMContext.reset(new qjs::Context(*(tls_VMRuntime.get())));
            initEnv(tls_VMContext);
        }
    };

    void VM::initEnv(std::shared_ptr<qjs::Context> spctx)
    {
        JSContext* ctx = spctx->ctx;
        JSRuntime* rt = JS_GetRuntime(ctx);

        using namespace qjs;

        js_std_init_handlers(rt);

        //HCE: loader for ES6 modules
        JS_SetModuleLoaderFunc(rt, nullptr, js_module_loader, nullptr);
        js_std_add_helpers(ctx, 0, nullptr);

        //HC: system modules
        js_init_module_std(ctx, "std");
        js_init_module_os(ctx, "os");

        auto& contractmod = spctx->addModule("ContractM");
        contractmod.class_<contract>("contract")
            .constructor<const qjs::Value&>()
            .fun<&contract::importas>("importas")
            .fun<&contract::call>("call");

        //HCE: make 'std' 'os' and 'contract' visible to non module code
        const char* str = "import * as std from 'std';\n"
            "import * as os from 'os';\n"
            "import * as hccontract from 'ContractM';\n"
            "globalThis.std = std;\n"
            "globalThis.os = os;\n"
            "globalThis.hccontract = hccontract;\n";

        const char* contr = "if(typeof contract === 'undefined') contract = new hccontract.contract(undefined);";
        try {
            spctx->eval(str, "<initEnv>", JS_EVAL_TYPE_MODULE);
            spctx->eval(contr, "<contract>");
        }
        catch (qjs::exception) {
            cerr << spctx->getExceptionDesc();
        }
        catch (std::exception& e) {
            cerr << e.what();
        }
    }

    bool VM::compileModule(const string& js_sourcecode, string& js_bytecode, string& excp_desc)
    {
        return compile(js_sourcecode, js_bytecode, excp_desc, JS_EVAL_TYPE_MODULE);
    }

    bool VM::compile(const string& js_sourcecode, string& js_bytecode, string& excp_desc, unsigned int compile_flags)
    {
        try {
            string_view vSrc(js_sourcecode);
            //HCE: Notice: don't change the second parameter value
            //HCE: else you must be keep consistent content with function of RenameModuleName
            qjs::Value obj = tls_VMContext->eval(vSrc, "compile", compile_flags | JS_EVAL_FLAG_COMPILE_ONLY | JS_EVAL_TYPE_GLOBAL);

            js_bytecode = tls_VMContext->dumpObject(obj);
            return true;
        }
        catch (qjs::exception) {
            excp_desc = tls_VMContext->getExceptionDesc();
        }
        catch (std::exception& e) {
            excp_desc = e.what();
        }

        return false;
    }

 } //HCE: namespace qjs
