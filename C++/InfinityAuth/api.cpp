#include "api.hpp"
#include "json.hpp"
#include "Curl/curl.h"
#include <windows.h>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <iostream>

using json = nlohmann::json;

namespace InfinityAuthV2 {

    API::API(std::string name, std::string ownerid, std::string secret, std::string version)
        : name(name), ownerid(ownerid), secret(secret), version(version) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    void API::setup() {
        init();
    }

    void API::setup(std::string name, std::string ownerid, std::string secret, std::string version) {
        this->name = name;
        this->ownerid = ownerid;
        this->secret = secret;
        this->version = version;
        init();
    }

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    void API::init() {
        if (name.empty()) return; 
        std::map<std::string, std::string> params;
        params["type"] = "init";
        params["ver"] = version;

        std::string raw_res = send_request(params);
        try {
            json j = json::parse(raw_res);
            if (j.contains("success") && j["success"].get<bool>()) {
                sessionid = j.value("sessionid", "");
            }
        } catch (...) {}
    }

    bool API::login(std::string username, std::string password) {
        std::map<std::string, std::string> params;
        params["type"] = "login";
        params["username"] = username;
        params["pass"] = password;
        params["hwid"] = get_hwid();
        params["sessionid"] = sessionid;

        std::string raw = send_request(params);
        Response res;
        try {
            json j = json::parse(raw);
            res.success = j.value("success", false);
            res.message = j.value("message", "");
            if (res.success && j.contains("info")) {
                auto info = j["info"];
                res.info.username = info.value("username", "");
                res.info.hwid = info.value("hwid", "");
                res.info.createdate = info.value("createdate", "");
                res.info.lastlogin = info.value("lastlogin", "");
                
                if (info.contains("subscriptions") && info["subscriptions"].is_array()) {
                    for (auto& s : info["subscriptions"]) {
                        Subscription sub;
                        sub.subscription = s.value("subscription", "");
                        sub.level = s.value("level", 1);
                        sub.expiry = s.value("expiry", "");
                        sub.timeleft = s.value("timeleft", 0);
                        res.info.subscriptions.push_back(sub);
                    }
                }
            }
        } catch (...) { res.success = false; res.message = "JSON Error"; }
        this->response = res;
        return res.success;
    }

    bool API::reg(std::string username, std::string password, std::string key) {
        std::map<std::string, std::string> params;
        params["type"] = "register";
        params["username"] = username;
        params["pass"] = password;
        params["key"] = key;
        params["hwid"] = get_hwid();
        params["sessionid"] = sessionid;

        std::string raw = send_request(params);
        Response res;
        try {
            json j = json::parse(raw);
            res.success = j.value("success", false);
            res.message = j.value("message", "");
            if (res.success && j.contains("info")) {
                auto info = j["info"];
                res.info.username = info.value("username", "");
                res.info.hwid = info.value("hwid", "");
                res.info.createdate = info.value("createdate", "");
                res.info.lastlogin = info.value("lastlogin", "");
                
                if (info.contains("subscriptions") && info["subscriptions"].is_array()) {
                    for (auto& s : info["subscriptions"]) {
                        Subscription sub;
                        sub.subscription = s.value("subscription", "");
                        sub.level = s.value("level", 1);
                        sub.expiry = s.value("expiry", "");
                        sub.timeleft = s.value("timeleft", 0);
                        res.info.subscriptions.push_back(sub);
                    }
                }
            }
        } catch (...) { res.success = false; }
        this->response = res;
        return res.success;
    }

    bool API::license(std::string key) {
        std::map<std::string, std::string> params;
        params["type"] = "license";
        params["key"] = key;
        params["hwid"] = get_hwid();
        params["sessionid"] = sessionid;

        std::string raw = send_request(params);
        Response res;
        try {
            json j = json::parse(raw);
            res.success = j.value("success", false);
            res.message = j.value("message", "");
            if (res.success && j.contains("info")) {
                auto info = j["info"];
                res.info.username = info.value("username", "");
                res.info.hwid = info.value("hwid", "");
                res.info.createdate = info.value("createdate", "");
                res.info.lastlogin = info.value("lastlogin", "");
                
                if (info.contains("subscriptions") && info["subscriptions"].is_array()) {
                    for (auto& s : info["subscriptions"]) {
                        Subscription sub;
                        sub.subscription = s.value("subscription", "");
                        sub.level = s.value("level", 1);
                        sub.expiry = s.value("expiry", "");
                        sub.timeleft = s.value("timeleft", 0);
                        res.info.subscriptions.push_back(sub);
                    }
                }
            }
        } catch (...) { res.success = false; }
        this->response = res;
        return res.success;
    }

    std::string API::get_var(std::string var_name) {
        std::map<std::string, std::string> params;
        params["type"] = "var";
        params["var"] = var_name;
        params["sessionid"] = sessionid;

        std::string raw = send_request(params);
        try {
            json j = json::parse(raw);
            if (j.value("success", false)) return j.value("value", "");
        } catch (...) {}
        return "";
    }

    void API::trigger_webhook(std::string webhook_name, std::string data) {
        std::map<std::string, std::string> params;
        params["type"] = "webhook";
        params["webhook"] = webhook_name;
        params["sessionid"] = sessionid;
        params["data"] = data;
        send_request(params);
    }

    std::string API::send_request(std::map<std::string, std::string> params) {
        CURL* curl = curl_easy_init();
        if (!curl) return "{\"success\":false}";

        json j_params;
        for (auto const& [key, val] : params) j_params[key] = val;
        
        std::string encrypted_data = encrypt(j_params.dump(), secret);
        std::string post_fields = "name=" + name + "&ownerid=" + ownerid + "&enc=1&data=" + encrypted_data;

        std::string response_string;
        curl_easy_setopt(curl, CURLOPT_URL, api_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Infinity API Client/3.0");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

        CURLcode res_code = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res_code != CURLE_OK) return "{\"success\":false,\"message\":\"Connection failed\"}";

        try {
            json j_res = json::parse(response_string);
            if (j_res.contains("enc") && j_res["enc"] == "1") {
                return decrypt(j_res["data"], secret);
            }
            return response_string;
        } catch (...) { return response_string; }
    }

    std::string API::get_hwid() {
        HW_PROFILE_INFOA hwProfileInfo;
        if (GetCurrentHwProfileA(&hwProfileInfo)) {
            return std::string(hwProfileInfo.szHwProfileGuid);
        }
        return "unknown";
    }

    // --- AES-256-CBC / Windows CryptoAPI (Elite Standard) ---
    // Esta versão usa a importação direta da chave SHA256 para total compatibilidade com o servidor Node.js.
    #include <wincrypt.h>
    #pragma comment(lib, "advapi32.lib")

    // Estrutura para importar chave bruta para a CryptoAPI
    struct AES256KeyBlob {
        BLOBHEADER hdr;
        DWORD cbKeySize;
        BYTE rgbKeyData[32];
    };

    std::string API::encrypt(std::string text, std::string key_str) {
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        HCRYPTHASH hHash = 0;

        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "";

        // Gerar o Hash SHA256 da Secret
        BYTE keyHash[32];
        DWORD dwHashLen = 32;
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptHashData(hHash, (BYTE*)key_str.c_str(), key_str.length(), 0);
            CryptGetHashParam(hHash, HP_HASHVAL, keyHash, &dwHashLen, 0);
            CryptDestroyHash(hHash);
        } else {
            CryptReleaseContext(hProv, 0);
            return "";
        }

        AES256KeyBlob blob;
        blob.hdr.bType = PLAINTEXTKEYBLOB;
        blob.hdr.bVersion = CUR_BLOB_VERSION;
        blob.hdr.reserved = 0;
        blob.hdr.aiKeyAlg = CALG_AES_256;
        blob.cbKeySize = 32;
        memcpy(blob.rgbKeyData, keyHash, 32);

        if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(blob), 0, 0, &hKey)) {
            CryptReleaseContext(hProv, 0);
            return "";
        }

        BYTE iv[16] = { 0 }; 
        CryptGenRandom(hProv, 16, iv); // Gera 16 bytes de IV Aleatório!
        CryptSetKeyParam(hKey, KP_IV, iv, 0);

        DWORD dwDataLen = text.length();
        DWORD dwBufLen = dwDataLen + 16;
        std::vector<BYTE> buffer(dwBufLen);
        memcpy(buffer.data(), text.c_str(), dwDataLen);

        if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &dwDataLen, dwBufLen)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return "";
        }

        buffer.resize(dwDataLen);
        std::vector<unsigned char> iv_vec(iv, iv + 16);
        std::string res = to_hex(iv_vec) + to_hex(std::vector<unsigned char>(buffer.begin(), buffer.end()));

        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return res;
    }

    std::string API::decrypt(std::string text, std::string key_str) {
        if (text.length() < 32) return "";

        std::string iv_hex = text.substr(0, 32);
        std::string cipher_hex = text.substr(32);

        std::vector<unsigned char> ivData = from_hex(iv_hex);
        std::vector<unsigned char> cipherData = from_hex(cipher_hex);
        
        if (cipherData.empty() || ivData.size() != 16) return "";

        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        HCRYPTHASH hHash = 0;

        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "";

        BYTE keyHash[32];
        DWORD dwHashLen = 32;
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptHashData(hHash, (BYTE*)key_str.c_str(), key_str.length(), 0);
            CryptGetHashParam(hHash, HP_HASHVAL, keyHash, &dwHashLen, 0);
            CryptDestroyHash(hHash);
        } else {
            CryptReleaseContext(hProv, 0);
            return "";
        }

        AES256KeyBlob blob;
        blob.hdr.bType = PLAINTEXTKEYBLOB;
        blob.hdr.bVersion = CUR_BLOB_VERSION;
        blob.hdr.reserved = 0;
        blob.hdr.aiKeyAlg = CALG_AES_256;
        blob.cbKeySize = 32;
        memcpy(blob.rgbKeyData, keyHash, 32);

        if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(blob), 0, 0, &hKey)) {
            CryptReleaseContext(hProv, 0);
            return "";
        }

        BYTE iv[16];
        memcpy(iv, ivData.data(), 16);
        CryptSetKeyParam(hKey, KP_IV, iv, 0);

        DWORD dwDataLen = cipherData.size();
        std::vector<BYTE> buffer = cipherData;

        if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer.data(), &dwDataLen)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return "";
        }

        std::string res((char*)buffer.data(), dwDataLen);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return res;
    }

    std::string API::to_hex(const std::vector<unsigned char>& data) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned char b : data) ss << std::setw(2) << (int)b;
        return ss.str();
    }

    std::vector<unsigned char> API::from_hex(std::string hex) {
        std::vector<unsigned char> res;
        try {
            for (size_t i = 0; i < (int)hex.length(); i += 2) {
                res.push_back((unsigned char)std::stoi(hex.substr(i, 2), nullptr, 16));
            }
        } catch (...) {}
        return res;
    }
}
