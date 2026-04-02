#include "cmd/commands.hpp"
#include "client/client.hpp"
#include "config/amanda_config.hpp"

#include <unistd.h>   // getpass

#include <iostream>
#include <stdexcept>
#include <string>

namespace amanda {

// ---------------------------------------------------------------------------
// oauth-setup   (admin only)
// Usage: amanda oauth-setup --username <name> [--save]
// POSTs to /admin/oauth2/setup and prints client_id and client_secret.
// With --save, stores client_id in ~/.sarekrc (oauth_client_id field).
// ---------------------------------------------------------------------------
void cmd_oauth_setup(HttpClient& client, AmandaConfig& cfg, const Args& args) {
    std::string username;
    bool save_id = false;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--username" && i + 1 < args.size())
            username = args[++i];
        else if (args[i] == "--save")
            save_id = true;
    }
    if (username.empty())
        throw std::runtime_error("usage: oauth-setup --username <name> [--save]");

    auto resp = client.post_json("/admin/oauth2/setup", {{"username", username}});

    std::string cid     = resp.at("client_id").get<std::string>();
    std::string csecret = resp.at("client_secret").get<std::string>();

    std::cout << "client_id:     " << cid     << "\n";
    std::cout << "client_secret: " << csecret << "\n";
    std::cout << "\nStore these securely. The client_secret will not be shown again.\n";

    if (save_id) {
        cfg.oauth_client_id = cid;
        save_config(cfg);
        std::cout << "client_id saved to ~/.sarekrc\n";
    }
}

// ---------------------------------------------------------------------------
// oauth-revoke   (admin only)
// Usage: amanda oauth-revoke --username <name>
// ---------------------------------------------------------------------------
void cmd_oauth_revoke(HttpClient& client, AmandaConfig& cfg, const Args& args) {
    (void)cfg;
    std::string username;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--username" && i + 1 < args.size())
            username = args[++i];
    }
    if (username.empty())
        throw std::runtime_error("usage: oauth-revoke --username <name>");

    auto resp = client.delete_with_body("/admin/oauth2/revoke", {{"username", username}});
    std::string status = resp.value("status", "unknown");
    if (status == "revoked")
        std::cout << "Revoked.\n";
    else
        std::cout << "No OAuth credentials found for '" << username << "'.\n";
}

// ---------------------------------------------------------------------------
// login-oauth
// Usage: amanda login-oauth [--client-id <id>] [--ttl <duration>]
// Reads client_id from ~/.sarekrc or --client-id flag, prompts for secret,
// exchanges for JWT, stores in $HOME/.sarek.oauth.
// ---------------------------------------------------------------------------
void cmd_login_oauth(HttpClient& client, AmandaConfig& cfg, const Args& args) {
    std::string client_id = cfg.oauth_client_id;
    std::string ttl_str;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--client-id" && i + 1 < args.size())
            client_id = args[++i];
        else if (args[i] == "--ttl" && i + 1 < args.size())
            ttl_str = args[++i];
    }

    if (client_id.empty()) {
        std::cout << "Client ID: " << std::flush;
        std::getline(std::cin, client_id);
    }
    if (client_id.empty())
        throw std::runtime_error("client_id is required");

    const char* secret_raw = getpass("Enter client secret: ");
    if (!secret_raw || *secret_raw == '\0')
        throw std::runtime_error("client secret may not be empty");
    std::string client_secret(secret_raw);

    nlohmann::json body{
        {"grant_type",    "client_credentials"},
        {"client_id",     client_id},
        {"client_secret", client_secret}
    };
    if (!ttl_str.empty())
        body["ttl"] = ttl_str;

    auto resp = client.post_json("/oauth/token", body);

    std::string jwt        = resp.at("access_token").get<std::string>();
    int64_t     expires_in = resp.value("expires_in", 3600LL);

    client.save_oauth_token(jwt);
    std::cout << "Logged in via OAuth (expires in "
              << expires_in << "s). Token stored in ~/.sarek.oauth\n";
}

} // namespace amanda
