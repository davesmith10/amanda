#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "client/client.hpp"

#include <crystals/crystals.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using json = nlohmann::json;

namespace amanda {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string token_file_path() {
    const char* home = std::getenv("HOME");
    if (!home) throw std::runtime_error("HOME not set");
    return std::string(home) + "/.sarek";
}

static void parse_url(const std::string& url,
                      bool& is_https, std::string& host, int& port) {
    if (url.size() >= 8 && url.substr(0, 8) == "https://") {
        is_https = true;
        std::string rest = url.substr(8);
        auto colon = rest.rfind(':');
        if (colon != std::string::npos) {
            host = rest.substr(0, colon);
            port = std::stoi(rest.substr(colon + 1));
        } else {
            host = rest;
            port = 443;
        }
    } else if (url.size() >= 7 && url.substr(0, 7) == "http://") {
        is_https = false;
        std::string rest = url.substr(7);
        auto colon = rest.rfind(':');
        if (colon != std::string::npos) {
            host = rest.substr(0, colon);
            port = std::stoi(rest.substr(colon + 1));
        } else {
            host = rest;
            port = 80;
        }
    } else {
        throw std::runtime_error("server URL must start with https:// or http://");
    }
}

static httplib::Headers make_headers(const std::string& token_b64) {
    httplib::Headers hdrs;
    if (!token_b64.empty())
        hdrs.emplace("Authorization", "Bearer " + token_b64);
    return hdrs;
}

static void check_response(const httplib::Result& res, const std::string& path,
                           HttpClient* client_for_401 = nullptr) {
    if (!res)
        throw std::runtime_error("HTTP request failed for " + path +
                                 ": " + httplib::to_string(res.error()));
    if (res->status >= 400) {
        std::string msg = "HTTP " + std::to_string(res->status) + ": " + path;
        try {
            auto j = json::parse(res->body);
            if (j.contains("error"))
                msg = j["error"].get<std::string>();
        } catch (...) {}
        // On 401 with token-revocation messages, auto-delete the local token
        if (res->status == 401 && client_for_401) {
            if (msg == "invalid token, please login" ||
                msg == "token revoked, please login") {
                client_for_401->delete_token();
            }
        }
        throw std::runtime_error(msg);
    }
}

// ---------------------------------------------------------------------------
// HttpClient
// ---------------------------------------------------------------------------

HttpClient::HttpClient(const AmandaConfig& cfg, bool insecure,
                       const std::string& cacert) {
    bool is_https; std::string host; int port;
    parse_url(cfg.server_url, is_https, host, port);
    is_https_   = is_https;
    token_path_ = token_file_path();

    if (is_https) {
        https_ = std::make_unique<httplib::SSLClient>(host, port);
        if (insecure) {
            https_->enable_server_certificate_verification(false);
        } else if (!cacert.empty()) {
            https_->set_ca_cert_path(cacert.c_str());
        }
    } else {
        http_ = std::make_unique<httplib::Client>(host, port);
    }
    load_token_from_file();
}

void HttpClient::load_token_from_file() {
    std::ifstream f(token_path_);
    if (!f.is_open()) return;
    std::string b64((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
    // Strip any trailing whitespace/newline
    while (!b64.empty() && (b64.back() == '\n' || b64.back() == '\r' || b64.back() == ' '))
        b64.pop_back();
    if (!b64.empty())
        token_b64_ = std::move(b64);
}

void HttpClient::save_token(const std::vector<uint8_t>& wire) {
    std::string b64 = base64_encode(wire.data(), wire.size());
    std::ofstream f(token_path_, std::ios::trunc);
    if (!f.is_open())
        throw std::runtime_error("Cannot write token to " + token_path_);
    f << b64 << '\n';
    f.close();
    chmod(token_path_.c_str(), 0600);
    token_b64_ = std::move(b64);
}

void HttpClient::delete_token() {
    ::unlink(token_path_.c_str());
    token_b64_.clear();
}

bool HttpClient::has_token() const {
    return !token_b64_.empty();
}

// ---------------------------------------------------------------------------
// HTTP verbs
// ---------------------------------------------------------------------------

nlohmann::json HttpClient::get(const std::string& path) {
    auto hdrs = make_headers(token_b64_);
    httplib::Result res;
    if (is_https_) res = https_->Get(path.c_str(), hdrs);
    else           res = http_->Get(path.c_str(), hdrs);
    check_response(res, path, this);
    return json::parse(res->body);
}

nlohmann::json HttpClient::post_json(const std::string& path, const nlohmann::json& body) {
    auto hdrs = make_headers(token_b64_);
    httplib::Result res;
    if (is_https_) res = https_->Post(path.c_str(), hdrs, body.dump(), "application/json");
    else           res = http_->Post(path.c_str(), hdrs, body.dump(), "application/json");
    check_response(res, path, this);
    return json::parse(res->body);
}

nlohmann::json HttpClient::post_binary(const std::string& path,
                                        const std::vector<uint8_t>& data,
                                        const std::string& content_type) {
    auto hdrs = make_headers(token_b64_);
    std::string body(data.begin(), data.end());
    httplib::Result res;
    if (is_https_) res = https_->Post(path.c_str(), hdrs, body, content_type.c_str());
    else           res = http_->Post(path.c_str(), hdrs, body, content_type.c_str());
    check_response(res, path, this);
    return json::parse(res->body);
}

nlohmann::json HttpClient::put_binary(const std::string& path,
                                       const std::vector<uint8_t>& data,
                                       const std::string& content_type) {
    auto hdrs = make_headers(token_b64_);
    std::string body(data.begin(), data.end());
    httplib::Result res;
    if (is_https_) res = https_->Put(path.c_str(), hdrs, body, content_type.c_str());
    else           res = http_->Put(path.c_str(), hdrs, body, content_type.c_str());
    check_response(res, path, this);
    return json::parse(res->body);
}

std::vector<uint8_t> HttpClient::get_binary(const std::string& path,
                                              std::string& content_type_out) {
    auto hdrs = make_headers(token_b64_);
    httplib::Result res;
    if (is_https_) res = https_->Get(path.c_str(), hdrs);
    else           res = http_->Get(path.c_str(), hdrs);
    check_response(res, path, this);
    content_type_out = res->get_header_value("Content-Type");
    return {res->body.begin(), res->body.end()};
}

nlohmann::json HttpClient::delete_(const std::string& path) {
    auto hdrs = make_headers(token_b64_);
    httplib::Result res;
    if (is_https_) res = https_->Delete(path.c_str(), hdrs);
    else           res = http_->Delete(path.c_str(), hdrs);
    check_response(res, path, this);
    return json::parse(res->body);
}

} // namespace amanda
