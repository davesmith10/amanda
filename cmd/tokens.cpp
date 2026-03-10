#include "cmd/commands.hpp"
#include "client/client.hpp"

#include <nlohmann/json.hpp>

#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

using json = nlohmann::json;

namespace amanda {

// Format unix epoch as human-readable UTC string
static std::string fmt_time(int64_t epoch) {
    std::time_t t = static_cast<std::time_t>(epoch);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%SZ", std::gmtime(&t));
    return buf;
}

// ---------------------------------------------------------------------------
// cmd_list_tokens — GET /admin/tokens
// ---------------------------------------------------------------------------

void cmd_list_tokens(HttpClient& client, AmandaConfig& /*cfg*/, const Args& /*args*/) {
    auto resp = client.get("/admin/tokens");

    if (!resp.is_array()) {
        std::cout << resp.dump(2) << "\n";
        return;
    }

    // Column header
    std::printf("%-36s  %-16s  %-20s  %-20s  %s\n",
                "TOKEN_ID", "USERNAME", "CREATED", "EXPIRES", "STATUS");
    std::printf("%-36s  %-16s  %-20s  %-20s  %s\n",
                "------------------------------------",
                "----------------",
                "--------------------",
                "--------------------",
                "-------");

    for (const auto& t : resp) {
        std::string token_id = t.value("token_id", "?");
        std::string username  = t.value("username",  "?");
        int64_t created       = t.value("created",   int64_t(0));
        int64_t expiry        = t.value("expiry",    int64_t(0));
        bool    revoked       = t.value("revoked",   false);
        std::string status    = revoked ? "REVOKED" : "active";

        std::printf("%-36s  %-16s  %-20s  %-20s  %s\n",
                    token_id.c_str(),
                    username.c_str(),
                    fmt_time(created).c_str(),
                    fmt_time(expiry).c_str(),
                    status.c_str());
    }
}

// ---------------------------------------------------------------------------
// cmd_revoke_token — DELETE /admin/tokens/<token_id>
// ---------------------------------------------------------------------------

void cmd_revoke_token(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    if (args.empty())
        throw std::runtime_error("usage: revoke-token <token_id>");

    std::string token_id = args[0];
    auto resp = client.delete_("/admin/tokens/" + token_id);
    std::cout << "Revoked token: " << token_id << "\n";
    (void)resp;
}

// ---------------------------------------------------------------------------
// cmd_revoke_tokens — DELETE /admin/tokens?username=<name>
// ---------------------------------------------------------------------------

void cmd_revoke_tokens(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    std::string username;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--username" && i + 1 < args.size())
            username = args[++i];
        else if (username.empty())
            username = args[i];
    }
    if (username.empty())
        throw std::runtime_error("usage: revoke-tokens <username>");

    auto resp = client.delete_("/admin/tokens?username=" + username);
    int count = resp.value("revoked", 0);
    std::cout << "Revoked " << count << " token(s) for user '" << username << "'\n";
}

// ---------------------------------------------------------------------------
// cmd_revoke_all — DELETE /admin/tokens  (no params = all tokens)
// ---------------------------------------------------------------------------

void cmd_revoke_all(HttpClient& client, AmandaConfig& /*cfg*/, const Args& /*args*/) {
    std::cerr << "This will revoke ALL active tokens and force all users to re-login.\n";
    std::cerr << "Type 'yes' to confirm: ";
    std::string confirm;
    std::getline(std::cin, confirm);
    if (confirm != "yes") {
        std::cout << "Aborted.\n";
        return;
    }

    auto resp = client.delete_("/admin/tokens");
    int count = resp.value("revoked", 0);
    std::cout << "Revoked " << count << " token(s). All users must re-login.\n";
}

} // namespace amanda
