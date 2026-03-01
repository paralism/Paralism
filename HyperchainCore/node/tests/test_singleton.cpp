// =============================================================================
// test_singleton.cpp — Singleton 模板单元测试
// 对应源文件: node/Singleton.h
// =============================================================================
#include <gtest/gtest.h>
#include "node/Singleton.h"
#include <string>

namespace {

class SimpleObj {
public:
    SimpleObj() : value(0) {}
    int value;
};

class ParamObj {
public:
    ParamObj(const std::string& n, int id) : name(n), m_id(id) {}
    std::string name;
    int m_id;
};

} // anonymous namespace

class SingletonTest : public ::testing::Test {
protected:
    void TearDown() override {
        Singleton<SimpleObj>::releaseInstance();
        Singleton<ParamObj, const std::string&, int>::releaseInstance();
    }
};

// SGL-01: 首次创建
TEST_F(SingletonTest, InstanceCreation) {
    auto* ptr = Singleton<SimpleObj>::instance();
    ASSERT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->value, 0);
}

// SGL-02: 获取已创建实例
TEST_F(SingletonTest, GetInstance) {
    Singleton<SimpleObj>::instance();
    auto* ptr = Singleton<SimpleObj>::getInstance();
    ASSERT_NE(ptr, nullptr);
}

// SGL-03: 唯一性
TEST_F(SingletonTest, Uniqueness) {
    auto* p1 = Singleton<SimpleObj>::instance();
    auto* p2 = Singleton<SimpleObj>::instance();
    EXPECT_EQ(p1, p2);
}

// SGL-04: 释放后返回 nullptr
TEST_F(SingletonTest, Release) {
    Singleton<SimpleObj>::instance();
    Singleton<SimpleObj>::releaseInstance();
    EXPECT_EQ(Singleton<SimpleObj>::getInstance(), nullptr);
}

// SGL-05: 带参数构造
TEST_F(SingletonTest, ParameterizedConstruction) {
    auto* ptr = Singleton<ParamObj, const std::string&, int>::instance("node_alpha", 42);
    ASSERT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->name, "node_alpha");
    EXPECT_EQ(ptr->m_id, 42);
}
