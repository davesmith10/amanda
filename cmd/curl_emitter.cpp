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

void CurlEmitter::emit_login      (const Args&) { throw std::runtime_error("emit_login: not yet implemented"); }
void CurlEmitter::emit_logout     (const Args&) { throw std::runtime_error("emit_logout: not yet implemented"); }
void CurlEmitter::emit_put        (const Args&) { throw std::runtime_error("emit_put: not yet implemented"); }
void CurlEmitter::emit_get        (const Args&) { throw std::runtime_error("emit_get: not yet implemented"); }
void CurlEmitter::emit_meta       (const Args&) { throw std::runtime_error("emit_meta: not yet implemented"); }
void CurlEmitter::emit_list       (const Args&) { throw std::runtime_error("emit_list: not yet implemented"); }
void CurlEmitter::emit_link       (const Args&) { throw std::runtime_error("emit_link: not yet implemented"); }
void CurlEmitter::emit_health     (const Args&) { throw std::runtime_error("emit_health: not yet implemented"); }
void CurlEmitter::emit_keygen     (const Args&) { throw std::runtime_error("emit_keygen: not yet implemented"); }
void CurlEmitter::emit_trays      (const Args&) { throw std::runtime_error("emit_trays: not yet implemented"); }
void CurlEmitter::emit_wrap       (const Args&) { throw std::runtime_error("emit_wrap: not yet implemented"); }
void CurlEmitter::emit_newuser    (const Args&) { throw std::runtime_error("emit_newuser: not yet implemented"); }
void CurlEmitter::emit_listuser   (const Args&) { throw std::runtime_error("emit_listuser: not yet implemented"); }
void CurlEmitter::emit_changepass (const Args&) { throw std::runtime_error("emit_changepass: not yet implemented"); }

} // namespace amanda
