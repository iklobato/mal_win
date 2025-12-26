#include <cstring>
#include <gtest/gtest.h>
#include <string>

// Mock Windows types for testing on non-Windows platforms
#ifndef _WIN32
typedef unsigned long DWORD;
typedef void *HKEY;
typedef void *HANDLE;
typedef int BOOL;
typedef unsigned short WORD;
typedef unsigned char BYTE;
#define ERROR_SUCCESS 0L
#define MAX_PATH 260
#define TRUE 1
#define FALSE 0
#endif

// Include utility functions from remote_command_executor.cpp
namespace Utils {
size_t strlen(const char *str) {
  if (!str)
    return 0;
  size_t len = 0;
  while (str[len] != '\0')
    len++;
  return len;
}

int strcmp(const char *s1, const char *s2) {
  if (!s1 || !s2)
    return (s1 == s2) ? 0 : (s1 ? 1 : -1);
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(unsigned char *)s1 - *(unsigned char *)s2;
}

char *strcpy(char *dest, const char *src) {
  if (!dest || !src)
    return dest;
  char *original = dest;
  while ((*dest++ = *src++))
    ;
  return original;
}

char *strcat(char *dest, const char *src) {
  if (!dest || !src)
    return dest;
  char *original = dest;
  while (*dest)
    dest++;
  while ((*dest++ = *src++))
    ;
  return original;
}

const char *strstr(const char *haystack, const char *needle) {
  if (!haystack || !needle)
    return nullptr;
  if (!*needle)
    return haystack;

  for (; *haystack; haystack++) {
    const char *h = haystack;
    const char *n = needle;
    while (*h && *n && (*h == *n)) {
      h++;
      n++;
    }
    if (!*n)
      return haystack;
  }
  return nullptr;
}

const char *strchr(const char *str, int c) {
  if (!str)
    return nullptr;
  while (*str) {
    if (*str == (char)c)
      return str;
    str++;
  }
  return (*str == (char)c) ? str : nullptr;
}

int atoi(const char *str) {
  if (!str)
    return 0;
  int result = 0;
  int sign = 1;

  while (*str == ' ' || *str == '\t')
    str++;

  if (*str == '-') {
    sign = -1;
    str++;
  } else if (*str == '+') {
    str++;
  }

  while (*str >= '0' && *str <= '9') {
    result = result * 10 + (*str - '0');
    str++;
  }

  return sign * result;
}

int snprintf(char *buffer, size_t size, const char *format, ...) {
  if (!buffer || !format || size == 0)
    return -1;
  // Simplified implementation for testing
  va_list args;
  va_start(args, format);
  int result = vsnprintf(buffer, size, format, args);
  va_end(args);
  return result;
}
} // namespace Utils

// ============================================================================
// UTILS CLASS TESTS
// ============================================================================

class UtilsTest : public ::testing::Test {
protected:
  char buffer[256];

  void SetUp() override { memset(buffer, 0, sizeof(buffer)); }
};

TEST_F(UtilsTest, StrlenBasic) {
  EXPECT_EQ(Utils::strlen("hello"), 5);
  EXPECT_EQ(Utils::strlen(""), 0);
  EXPECT_EQ(Utils::strlen("a"), 1);
  EXPECT_EQ(Utils::strlen(nullptr), 0);
}

TEST_F(UtilsTest, StrlenLongString) {
  const char *longStr = "This is a longer string for testing";
  EXPECT_EQ(Utils::strlen(longStr), 35);
}

TEST_F(UtilsTest, StrcmpEqual) {
  EXPECT_EQ(Utils::strcmp("hello", "hello"), 0);
  EXPECT_EQ(Utils::strcmp("", ""), 0);
  EXPECT_EQ(Utils::strcmp("test", "test"), 0);
}

TEST_F(UtilsTest, StrcmpNotEqual) {
  EXPECT_LT(Utils::strcmp("abc", "abd"), 0);
  EXPECT_GT(Utils::strcmp("abd", "abc"), 0);
  EXPECT_NE(Utils::strcmp("hello", "world"), 0);
}

TEST_F(UtilsTest, StrcmpNullHandling) {
  EXPECT_EQ(Utils::strcmp(nullptr, nullptr), 0);
  EXPECT_GT(Utils::strcmp("test", nullptr), 0);
  EXPECT_LT(Utils::strcmp(nullptr, "test"), 0);
}

TEST_F(UtilsTest, StrcpyBasic) {
  Utils::strcpy(buffer, "hello");
  EXPECT_STREQ(buffer, "hello");
}

TEST_F(UtilsTest, StrcpyEmpty) {
  Utils::strcpy(buffer, "");
  EXPECT_STREQ(buffer, "");
}

TEST_F(UtilsTest, StrcpyOverwrite) {
  Utils::strcpy(buffer, "first");
  Utils::strcpy(buffer, "second");
  EXPECT_STREQ(buffer, "second");
}

TEST_F(UtilsTest, StrcpyNullHandling) {
  Utils::strcpy(buffer, "test");
  Utils::strcpy(buffer, nullptr);
  // Should not crash, buffer unchanged
  EXPECT_STREQ(buffer, "test");
}

TEST_F(UtilsTest, StrcatBasic) {
  Utils::strcpy(buffer, "hello");
  Utils::strcat(buffer, " world");
  EXPECT_STREQ(buffer, "hello world");
}

TEST_F(UtilsTest, StrcatEmpty) {
  Utils::strcpy(buffer, "test");
  Utils::strcat(buffer, "");
  EXPECT_STREQ(buffer, "test");
}

TEST_F(UtilsTest, StrcatMultiple) {
  Utils::strcpy(buffer, "a");
  Utils::strcat(buffer, "b");
  Utils::strcat(buffer, "c");
  EXPECT_STREQ(buffer, "abc");
}

TEST_F(UtilsTest, StrstrFound) {
  const char *result = Utils::strstr("hello world", "world");
  EXPECT_NE(result, nullptr);
  EXPECT_STREQ(result, "world");
}

TEST_F(UtilsTest, StrstrNotFound) {
  const char *result = Utils::strstr("hello world", "xyz");
  EXPECT_EQ(result, nullptr);
}

TEST_F(UtilsTest, StrstrEmptyNeedle) {
  const char *haystack = "test";
  const char *result = Utils::strstr(haystack, "");
  EXPECT_EQ(result, haystack);
}

TEST_F(UtilsTest, StrstrNullHandling) {
  EXPECT_EQ(Utils::strstr(nullptr, "test"), nullptr);
  EXPECT_EQ(Utils::strstr("test", nullptr), nullptr);
}

TEST_F(UtilsTest, StrchrFound) {
  const char *result = Utils::strchr("hello", 'e');
  EXPECT_NE(result, nullptr);
  EXPECT_EQ(*result, 'e');
}

TEST_F(UtilsTest, StrchrNotFound) {
  const char *result = Utils::strchr("hello", 'x');
  EXPECT_EQ(result, nullptr);
}

TEST_F(UtilsTest, StrchrNullTerminator) {
  const char *str = "test";
  const char *result = Utils::strchr(str, '\0');
  EXPECT_NE(result, nullptr);
  EXPECT_EQ(*result, '\0');
}

TEST_F(UtilsTest, AtoiPositive) {
  EXPECT_EQ(Utils::atoi("123"), 123);
  EXPECT_EQ(Utils::atoi("0"), 0);
  EXPECT_EQ(Utils::atoi("999"), 999);
}

TEST_F(UtilsTest, AtoiNegative) {
  EXPECT_EQ(Utils::atoi("-123"), -123);
  EXPECT_EQ(Utils::atoi("-1"), -1);
}

TEST_F(UtilsTest, AtoiWithWhitespace) {
  EXPECT_EQ(Utils::atoi("  123"), 123);
  EXPECT_EQ(Utils::atoi("\t456"), 456);
}

TEST_F(UtilsTest, AtoiWithSign) {
  EXPECT_EQ(Utils::atoi("+123"), 123);
  EXPECT_EQ(Utils::atoi("-456"), -456);
}

TEST_F(UtilsTest, AtoiInvalid) {
  EXPECT_EQ(Utils::atoi("abc"), 0);
  EXPECT_EQ(Utils::atoi(""), 0);
  EXPECT_EQ(Utils::atoi(nullptr), 0);
}

// ============================================================================
// JSON PARSER TESTS
// ============================================================================

class JsonParser {
public:
  bool parse(const std::string &json, std::string &command, std::string &next,
             int &sleep) {
    if (json.empty())
      return false;

    // Find "command" field
    const char *cmdStart = Utils::strstr(json.c_str(), "\"command\"");
    if (!cmdStart)
      return false;

    cmdStart = Utils::strchr(cmdStart, ':');
    if (!cmdStart)
      return false;
    cmdStart++;

    while (*cmdStart == ' ' || *cmdStart == '\t')
      cmdStart++;

    if (*cmdStart != '\"')
      return false;
    cmdStart++;

    const char *cmdEnd = cmdStart;
    while (*cmdEnd && *cmdEnd != '\"')
      cmdEnd++;

    command = std::string(cmdStart, cmdEnd - cmdStart);

    // Find "next" field
    const char *nextStart = Utils::strstr(json.c_str(), "\"next\"");
    if (!nextStart)
      return false;

    nextStart = Utils::strchr(nextStart, ':');
    if (!nextStart)
      return false;
    nextStart++;

    while (*nextStart == ' ' || *nextStart == '\t')
      nextStart++;

    if (*nextStart != '\"')
      return false;
    nextStart++;

    const char *nextEnd = nextStart;
    while (*nextEnd && *nextEnd != '\"')
      nextEnd++;

    next = std::string(nextStart, nextEnd - nextStart);

    // Find "sleep" field
    const char *sleepStart = Utils::strstr(json.c_str(), "\"sleep\"");
    if (!sleepStart)
      return false;

    sleepStart = Utils::strchr(sleepStart, ':');
    if (!sleepStart)
      return false;
    sleepStart++;

    while (*sleepStart == ' ' || *sleepStart == '\t')
      sleepStart++;

    sleep = Utils::atoi(sleepStart);

    return true;
  }
};

class JsonParserTest : public ::testing::Test {
protected:
  JsonParser parser;
  std::string command;
  std::string next;
  int sleep;

  void SetUp() override {
    command.clear();
    next.clear();
    sleep = 0;
  }
};

TEST_F(JsonParserTest, ParseValidJson) {
  std::string json =
      R"({"command": "whoami", "next": "server.com", "sleep": 30})";
  EXPECT_TRUE(parser.parse(json, command, next, sleep));
  EXPECT_EQ(command, "whoami");
  EXPECT_EQ(next, "server.com");
  EXPECT_EQ(sleep, 30);
}

TEST_F(JsonParserTest, ParseWithSpaces) {
  std::string json =
      R"({ "command" : "test" , "next" : "host" , "sleep" : 60 })";
  EXPECT_TRUE(parser.parse(json, command, next, sleep));
  EXPECT_EQ(command, "test");
  EXPECT_EQ(next, "host");
  EXPECT_EQ(sleep, 60);
}

TEST_F(JsonParserTest, ParseEmptyJson) {
  std::string json = "";
  EXPECT_FALSE(parser.parse(json, command, next, sleep));
}

TEST_F(JsonParserTest, ParseMissingCommand) {
  std::string json = R"({"next": "server.com", "sleep": 30})";
  EXPECT_FALSE(parser.parse(json, command, next, sleep));
}

TEST_F(JsonParserTest, ParseMissingNext) {
  std::string json = R"({"command": "whoami", "sleep": 30})";
  EXPECT_FALSE(parser.parse(json, command, next, sleep));
}

TEST_F(JsonParserTest, ParseMissingSleep) {
  std::string json = R"({"command": "whoami", "next": "server.com"})";
  EXPECT_FALSE(parser.parse(json, command, next, sleep));
}

TEST_F(JsonParserTest, ParseComplexCommand) {
  std::string json =
      R"({"command": "cmd /c echo test", "next": "192.168.1.1", "sleep": 120})";
  EXPECT_TRUE(parser.parse(json, command, next, sleep));
  EXPECT_EQ(command, "cmd /c echo test");
  EXPECT_EQ(next, "192.168.1.1");
  EXPECT_EQ(sleep, 120);
}

TEST_F(JsonParserTest, ParseZeroSleep) {
  std::string json = R"({"command": "test", "next": "host", "sleep": 0})";
  EXPECT_TRUE(parser.parse(json, command, next, sleep));
  EXPECT_EQ(sleep, 0);
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
