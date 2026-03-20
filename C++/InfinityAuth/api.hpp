#pragma once
#include <string>
#include <vector>
#include <map>
#include <windows.h>

namespace InfinityAuthV2 {

    struct Response {
        bool success;
        std::string message;
        struct {
            std::string username;
            std::string hwid;
        } info;
    };

    class API {
    public:
        API(std::string name, std::string ownerid, std::string secret, std::string version);

        void init();
        Response login(std::string username, std::string password);
        Response register_user(std::string username, std::string password, std::string key);
        Response license(std::string key);
        
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
