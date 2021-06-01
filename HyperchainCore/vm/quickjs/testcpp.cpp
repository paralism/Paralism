//https://github.com/ftk/quickjspp

#include "quickjspp.h"
#include <iostream>
#include <string>
using namespace std;

class MyClass
{
public:
    MyClass() {}
    MyClass(std::vector<int>) {}

    double member_variable = 5.5;
    std::string member_function(const std::string& s) { return "Hello, " + s; }
};

int println(const std::string& str) { std::cout << str << std::endl; return 100000; }

int main()
{
    //auto a = JSValueUnion{ .int32 = 1 };
    //a.int32 = 2;
    qjs::Runtime runtime;
    qjs::Context context(runtime);
    try
    {
        // export classes as a module
        auto ret = context.evalFile("E:\\workspace\\git\\vm\\buildwin64\\bin\\Debug\\qjsc_test.bin", true);
        std::cout << "output: " << (std::string)ret << endl;

        auto& module = context.addModule("MyModule");
        module.function<&println>("println");
        module.class_<MyClass>("MyClass")
            .constructor<>()
            .constructor<std::vector<int>>("MyClassA")
            //.fun<double MyClass::*, &MyClass::member_variable>("member_variable");
            .fun<&MyClass::member_variable>("member_variable")
            //.fun(&MyClass::member_variable, "member_variable");
            .fun<&MyClass::member_function>("member_function");
        // import module
        //context.eval("import * as my from 'MyModule'; globalThis.my = my;", "<import>", JS_EVAL_TYPE_MODULE);
        context.eval("import * as my from 'MyModule';", "<import>", JS_EVAL_TYPE_MODULE);
        // evaluate js code
        auto xxx = context.eval("let v1 = new my.MyClass();" "\n"
            "v1.member_variable = 1;" "\n"
            "let v2 = new my.MyClassA([1,2,3]);" "\n"
            "my.println(v2.member_function(\"yage is good\"));" "\n"
            "x = 999;" "\n"
            "998;" "\n"
            "function my_callback(str) {" "\n"
            "  my.println(v2.member_function(str));" "\n"
            "}" "\n");

            std::cout << "output: " << (std::string)xxx << endl;

        // callback
        auto cb = (std::function<void(const std::string&)>) context.eval("my_callback");
        cb("world");
    }
    catch(qjs::exception)
    {
        auto exc = context.getException();
        std::cerr << (std::string) exc << std::endl;
        if((bool) exc["stack"])
            std::cerr << (std::string) exc["stack"] << std::endl;
        return 1;
    }
}