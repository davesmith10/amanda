#include "cmd/curl_emitter.hpp"
#include <fmt/format.h>
#include <iostream>
#include <stdexcept>

namespace amanda {

CurlEmitter::CurlEmitter(const AmandaConfig& cfg, bool insecure,
                         const std::string& token_b64)
    : cfg_(cfg), insecure_(insecure), token_b64_(token_b64)
{
    server_url_ = cfg_.server_url;
    // Strip trailing slash if present
    if (!server_url_.empty() && server_url_.back() == '/')
        server_url_.pop_back();
}

std::string CurlEmitter::tls_flags() const {
    if (insecure_) return "-k";
    if (!cfg_.cacert.empty()) return "--cacert " + cfg_.cacert;
    return "";
}

std::string CurlEmitter::token_line() const {
    if (!token_b64_.empty())
        return fmt::format("TOKEN={}\n", token_b64_);
    return "TOKEN=<your-bearer-token>\n";
}

std::string CurlEmitter::host_line() const {
    return fmt::format("HOST={}\n", server_url_);
}

std::string CurlEmitter::auth_preamble() const {
    return host_line() + token_line();
}

void CurlEmitter::emit_login(const Args& args) {
    std::unordered_map<std::string, std::string> d;
    d["host"]     = server_url_;
    d["tls"]      = tls_flags();
    d["username"] = cfg_.username.empty() ? "<username>" : cfg_.username;
    d["password"] = "<password>";   // interactive; placeholder by design

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--username" && i + 1 < args.size())
            d["username"] = args[++i];
    }

    std::string tls = d["tls"].empty() ? "" : " " + d["tls"];
    std::cout << fmt::format(
        "TOKEN=$(curl -s{tls} -X POST \"{host}/login\" \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -d '{{\"username\":\"{username}\",\"password\":\"{password}\"}}' \\\n"
        "  | jq -r .token)\n"
        "\n"
        "echo \"Token: $TOKEN\"\n",
        fmt::arg("tls",      tls),
        fmt::arg("host",     d["host"]),
        fmt::arg("username", d["username"]),
        fmt::arg("password", d["password"])
    ) << "\n";
}

void CurlEmitter::emit_logout(const Args& /*args*/) {
    std::unordered_map<std::string, std::string> d;
    d["host"] = server_url_;
    d["tls"]  = tls_flags();

    std::string tls = d["tls"].empty() ? "" : " " + d["tls"];
    std::cout << auth_preamble()
              << fmt::format(
        "curl -s{tls} -X DELETE \"{host}/logout\" \\\n"
        "  -H \"Authorization: Bearer $TOKEN\"\n",
        fmt::arg("tls",  tls),
        fmt::arg("host", d["host"])
    ) << "\n";
}

void CurlEmitter::emit_put        (const Args&) { throw std::runtime_error("emit_put: not yet implemented"); }
void CurlEmitter::emit_get        (const Args&) { throw std::runtime_error("emit_get: not yet implemented"); }
void CurlEmitter::emit_meta       (const Args&) { throw std::runtime_error("emit_meta: not yet implemented"); }
void CurlEmitter::emit_list       (const Args&) { throw std::runtime_error("emit_list: not yet implemented"); }
void CurlEmitter::emit_link       (const Args&) { throw std::runtime_error("emit_link: not yet implemented"); }

void CurlEmitter::emit_health(const Args& /*args*/) {
    std::unordered_map<std::string, std::string> d;
    d["host"] = server_url_;
    d["tls"]  = tls_flags();

    std::string tls = d["tls"].empty() ? "" : " " + d["tls"];
    std::cout << fmt::format(
        "curl -s{tls} -X GET \"{host}/health\"\n",
        fmt::arg("tls",  tls),
        fmt::arg("host", d["host"])
    ) << "\n";
}
void CurlEmitter::emit_keygen     (const Args&) { throw std::runtime_error("emit_keygen: not yet implemented"); }
void CurlEmitter::emit_trays      (const Args&) { throw std::runtime_error("emit_trays: not yet implemented"); }
void CurlEmitter::emit_wrap       (const Args&) { throw std::runtime_error("emit_wrap: not yet implemented"); }
void CurlEmitter::emit_newuser    (const Args&) { throw std::runtime_error("emit_newuser: not yet implemented"); }
void CurlEmitter::emit_listuser   (const Args&) { throw std::runtime_error("emit_listuser: not yet implemented"); }
void CurlEmitter::emit_changepass (const Args&) { throw std::runtime_error("emit_changepass: not yet implemented"); }

} // namespace amanda
