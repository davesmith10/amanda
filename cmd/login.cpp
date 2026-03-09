#include "cmd/commands.hpp"
#include "client/client.hpp"

#include <crystals/base64.hpp>
#include <crystals/token_format.hpp>

#include <unistd.h>   // getpass

#include <ctime>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

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

// ---------------------------------------------------------------------------
// whoami
// ---------------------------------------------------------------------------
// Reads the local token file and prints the logged-in username, assertions,
// and expiry time. No server contact required.
// ---------------------------------------------------------------------------
void cmd_whoami(HttpClient& client, AmandaConfig& /*cfg*/, const Args& /*args*/) {
    if (!client.has_token())
        throw std::runtime_error("not logged in (no token file found)");

    auto wire = base64_decode(client.token_b64());
    Token tok = token_unpack(wire);

    // Extract username and other assertions from the data field
    std::string data_str(tok.data.begin(), tok.data.end());
    std::string username;
    std::vector<std::string> assertions;
    {
        std::istringstream ss(data_str);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty()) continue;
            if (line.substr(0, 4) == "usr:")
                username = line.substr(4);
            else
                assertions.push_back(line);
        }
    }

    if (username.empty())
        throw std::runtime_error("token has no usr: assertion");

    int64_t now = static_cast<int64_t>(std::time(nullptr));
    bool expired = (now >= tok.expires_at);

    std::cout << username << "\n";

    // Format expiry as a human-readable local time
    std::time_t exp_t = static_cast<std::time_t>(tok.expires_at);
    char time_buf[64];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&exp_t));
    std::cout << "expires: " << time_buf;
    if (expired) std::cout << "  [EXPIRED]";
    std::cout << "\n";

    if (!assertions.empty()) {
        std::cout << "scope:";
        for (const auto& a : assertions)
            std::cout << "   " << a;
        std::cout << "\n";
    }
}

} // namespace amanda
