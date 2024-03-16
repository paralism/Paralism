/*Copyright 2016-2024 hyperchain.net (Hyperchain)

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

#pragma once

#include "quickjs/quickjspp.h"

extern thread_local std::shared_ptr<qjs::Runtime> tls_VMRuntime;
extern thread_local std::shared_ptr<qjs::Context> tls_VMContext;
extern thread_local std::shared_ptr<qjs::Context> tls_VMContext_Exec;


namespace qjs {

    //HCE: Javascript virtual machine, which compiles and executes JS code
    class VM
    {
    public:
        VM();

        static qjs::Context* getCtx() {
            return tls_VMContext.get();
        }

        static qjs::Context* getCtxExec() {
            return tls_VMContext_Exec.get();
        }

        //HCE: compile JS source code to JS byte code
        //HCE: @para js_sourcecode String of JS source code
        //HCE: @para js_bytecode String of JS byte code
        //HCE: @para excp_desc String of exception
        //HCE: @returns True if success
        bool compileModule(const string& js_sourcecode, string& js_bytecode, string& excp_desc);
        bool compile(const string& js_sourcecode, string& js_bytecode, string& excp_desc, unsigned int compile_flags = 0);

        template<typename T>
        bool execute(const string& js_bytecode, T& result, string& excp_desc)
        {
            try {
                tls_VMContext_Exec.reset(new qjs::Context(*(tls_VMRuntime.get())));
                executeIsolated(tls_VMContext_Exec, js_bytecode, result);
                return true;
            }
            catch (qjs::exception) {
                excp_desc = tls_VMContext_Exec->getExceptionDesc();
            }
            catch (std::exception& e) {
                excp_desc = e.what();
            }
            return false;
        }

        template<typename T>
        static void executeIsolated(std::shared_ptr<qjs::Context>& spctx, const string& js_bytecode, T& result)
        {
            //HCE: init environment
            //HCE: @para spctx Pointer to Context
            //HCE: @returns void
            initEnv(spctx);

            string_view code(js_bytecode);
            qjs::Value obj = spctx->evalBinary(code);
            result = (T)obj;
        }


    private:
        static void initEnv(std::shared_ptr<qjs::Context> spctx);
    };


} //HCE: namespace qjs
