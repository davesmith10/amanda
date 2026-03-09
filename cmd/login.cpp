#include "cmd/commands.hpp"
#include "client/client.hpp"

#include <crystals/base64.hpp>

#include <unistd.h>   // getpass

#include <iostream>
#include <stdexcept>
#include <string>

namespace amanda {

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------
// Usage:
//   amanda login [--username <name>]
//   amanda login --token <base64>   (first-login after invite)
// ---------------------------------------------------------------------------
void cmd_login(HttpClient& client, AmandaConfig& cfg, const Args& args) {
    std::string username;
    std::string token_arg;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--username" && i + 1 < args.size()) {
            username = args[++i];
        } else if (args[i] == "--token" && i + 1 < args.size()) {
            token_arg = args[++i];
        }
    }

    if (!token_arg.empty()) {
        // Invite flow: decode token, save it, then set password
        auto wire = base64_decode(token_arg);
        client.save_token(wire);

        const char* pw1 = getpass("Set password: ");
        std::string p1(pw1);
        const char* pw2 = getpass("Confirm password: ");
        if (p1 != std::string(pw2))
            throw std::runtime_error("Passwords do not match");

        client.post_json("/users/password", {{"password", p1}});
        std::cout << "Password set. Logged in.\n";
        return;
    }

    // Normal password login
    if (username.empty()) username = cfg.username;  // fall back to ~/.sarekrc
    if (username.empty()) {
        std::cout << "Username: " << std::flush;
        std::getline(std::cin, username);
    }
    const char* pw = getpass("Password: ");
    std::string password(pw);

    auto resp = client.post_json("/login",
        {{"username", username}, {"password", password}});
    std::string token_b64 = resp.at("token").get<std::string>();
    auto wire = base64_decode(token_b64);
    client.save_token(wire);
    std::cout << "Logged in as " << resp.at("username").get<std::string>() << "\n";
}

// ---------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------
void cmd_logout(HttpClient& client, AmandaConfig& /*cfg*/, const Args& /*args*/) {
    client.delete_("/logout");
    client.delete_token();
    std::cout << "Logged out\n";
}

} // namespace amanda
