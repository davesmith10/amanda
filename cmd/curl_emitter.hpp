#pragma once

#include "config/amanda_config.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace amanda {

using Args = std::vector<std::string>;

// Emits functional bash/curl commands to stdout for each amanda CLI command.
// Constructed once per --curl invocation; methods map 1:1 to cmd_* functions.
class CurlEmitter {
public:
    // cfg        — loaded ~/.sarekrc (server_url, default_tray, username, cacert)
    // insecure   — corresponds to --insecure global flag
    // token_b64  — current bearer token (base64), or empty string if not logged in
    CurlEmitter(const AmandaConfig& cfg, bool insecure,
                const std::string& token_b64);

    void emit_login      (const Args& args);
    void emit_logout     (const Args& args);
    void emit_put        (const Args& args);
    void emit_get        (const Args& args);
    void emit_meta       (const Args& args);
    void emit_list       (const Args& args);
    void emit_link       (const Args& args);
    void emit_health     (const Args& args);
    void emit_keygen     (const Args& args);
    void emit_trays      (const Args& args);
    void emit_wrap       (const Args& args);
    void emit_newuser    (const Args& args);
    void emit_listuser   (const Args& args);
    void emit_changepass (const Args& args);

private:
    // Returns the curl TLS flags string: "-k", "--cacert /path", or ""
    std::string tls_flags() const;

    // Returns "TOKEN=<token_b64_>\n" or "TOKEN=<your-bearer-token>\n" if empty
    std::string token_line() const;

    // Returns "HOST=<server_url_>\n"
    std::string host_line() const;

    // Common preamble for auth'd commands: HOST= + TOKEN= lines
    std::string auth_preamble() const;

    const AmandaConfig& cfg_;
    bool insecure_;
    std::string token_b64_;
    std::string server_url_;   // cfg_.server_url (with no trailing slash)
};

} // namespace amanda
