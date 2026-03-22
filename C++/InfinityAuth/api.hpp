#pragma once
#include <string>
#include <vector>
#include <map>
#include <windows.h>

namespace InfinityAuth {

    struct Subscription {
        std::string subscription;
        int level;
        std::string expiry;
        int timeleft;
    };

    struct Response {
        bool success;
        std::string message;
        struct {
            std::string username;
            std::string hwid;
            std::string createdate;
            std::string lastlogin;
            std::vector<Subscription> subscriptions;
        } info;
    };

    class API {
    public:
        API() = default;
        API(std::string name, std::string ownerid, std::string secret, std::string version);

        void init();
        void setup();
        void setup(std::string name, std::string ownerid, std::string secret, std::string version);
        
        bool login(std::string username, std::string password);
        bool reg(std::string username, std::string password, std::string key);
        bool register_user(std::string username, std::string password, std::string key) {
            return reg(username, password, key);
        }
        bool license(std::string key);
        
        Response response;
        
        // V3 Novidades
        std::string get_var(std::string var_name);
        void trigger_webhook(std::string webhook_name, std::string data = "");

    private:
        std::string name, ownerid, secret, version;
        std::string sessionid;
        std::string api_url = "https://infinityauth.shardweb.app/api/InfinityAuth/";

        std::string send_request(std::map<std::string, std::string> params);
        std::string get_hwid();
        
        // Criptografia V3 (AES-256-CBC via Wincrypt)
        std::string encrypt(std::string text, std::string key);
        std::string decrypt(std::string text, std::string key);
        
        std::string to_hex(const std::vector<unsigned char>& data);
        std::vector<unsigned char> from_hex(std::string hex);
    };
}

using InfinityAuthApp = InfinityAuth::API;
using api = InfinityAuth::API;
