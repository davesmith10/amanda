#pragma once

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "config/amanda_config.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace amanda {

class HttpClient {
public:
    // insecure: skip TLS certificate verification entirely
    // cacert:   path to PEM CA certificate (or the server's self-signed cert) to
    //           use for verification instead of the system CA bundle
    explicit HttpClient(const AmandaConfig& cfg,
                        bool insecure = false,
                        const std::string& cacert = {});

    nlohmann::json get(const std::string& path);
    nlohmann::json post_json(const std::string& path, const nlohmann::json& body);
    nlohmann::json post_binary(const std::string& path,
                               const std::vector<uint8_t>& data,
                               const std::string& content_type);
    nlohmann::json put_binary(const std::string& path,
                              const std::vector<uint8_t>& data,
                              const std::string& content_type);
    std::vector<uint8_t> get_binary(const std::string& path,
                                    std::string& content_type_out);
    nlohmann::json delete_(const std::string& path);

    void save_token(const std::vector<uint8_t>& wire); // writes $HOME/.sarek, chmod 0600
    void delete_token();
    bool has_token() const;
    const std::string& token_b64() const { return token_b64_; }

private:
    void load_token_from_file();

    std::unique_ptr<httplib::SSLClient> https_;
    std::unique_ptr<httplib::Client>    http_;
    bool        is_https_   = true;
    std::string token_b64_;
    std::string token_path_;
};

} // namespace amanda
