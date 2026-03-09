#include "cmd/commands.hpp"
#include "client/client.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using json = nlohmann::json;

namespace amanda {

// ---------------------------------------------------------------------------
// newuser (admin only)
// ---------------------------------------------------------------------------
// Usage:
//   amanda newuser --username <name> [--assert <scope> ...]
//
// Prints the base64 invite token to stdout; admin sends it to the new user.
// ---------------------------------------------------------------------------
void cmd_newuser(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    std::string username;
    std::vector<std::string> assertions;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--username" && i + 1 < args.size()) {
            username = args[++i];
        } else if (args[i] == "--assert" && i + 1 < args.size()) {
            assertions.push_back(args[++i]);
        }
    }

    if (username.empty())
        throw std::invalid_argument("newuser: --username is required");

    json body = {{"username", username}};
    if (!assertions.empty()) {
        json arr = json::array();
        for (const auto& a : assertions) arr.push_back(a);
        body["assertions"] = arr;
    }

    auto resp = client.post_json("/users/invite", body);
    // Print the base64 token to stdout so the admin can pipe it to a file
    std::cout << resp.at("token").get<std::string>() << "\n";
}

// ---------------------------------------------------------------------------
// listuser
// ---------------------------------------------------------------------------
// Usage:
//   amanda listuser
//
// Calls GET /users. Admin sees all users with full detail; non-admin sees
// own row with full detail and other users name-only.
// ---------------------------------------------------------------------------
void cmd_listuser(HttpClient& client, AmandaConfig& cfg, const Args& /*args*/) {
    auto resp = client.get("/users");
    const auto& users = resp.at("users");

    // Determine "you" username: from cfg, or from own usr: assertion in data
    std::string me = cfg.username;
    if (me.empty()) {
        for (const auto& u : users) {
            if (u.contains("assertions")) {
                for (const auto& a : u.at("assertions")) {
                    std::string as = a.get<std::string>();
                    if (as.size() > 4 && as.substr(0, 4) == "usr:") {
                        me = as.substr(4);
                        break;
                    }
                }
            }
            if (!me.empty()) break;
        }
    }

    // Header
    std::cout << std::left
              << std::setw(16) << "USERNAME"
              << std::setw(21) << "USER_ID"
              << std::setw(14) << "FLAGS"
              << "ASSERTIONS\n";

    for (const auto& u : users) {
        std::string uname = u.at("username").get<std::string>();
        bool is_me = (uname == me);

        std::cout << std::left << std::setw(16) << uname;

        if (u.contains("user_id")) {
            uint64_t uid = u.at("user_id").get<uint64_t>();
            std::cout << std::setw(21) << uid;

            std::string flags;
            if (u.value("admin",  false)) flags += "admin";
            if (u.value("locked", false)) { if (!flags.empty()) flags += ","; flags += "locked"; }
            std::cout << std::setw(14) << flags;

            bool first = true;
            for (const auto& a : u.at("assertions")) {
                if (!first) std::cout << " ";
                std::cout << a.get<std::string>();
                first = false;
            }
        } else {
            // name-only row (non-admin, other user)
            std::cout << std::setw(21) << "" << std::setw(14) << "";
        }

        if (is_me) std::cout << "   [you]";
        std::cout << "\n";
    }
}

// ---------------------------------------------------------------------------
// changepass
// ---------------------------------------------------------------------------
// Usage:
//   amanda changepass [--username <name>]
//
// Changes the password for the given user (defaults to own username).
// Prompts for new password and confirmation via getpass().
// ---------------------------------------------------------------------------
void cmd_changepass(HttpClient& client, AmandaConfig& cfg, const Args& args) {
    std::string username = cfg.username;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--username" && i + 1 < args.size())
            username = args[++i];
    }

    if (username.empty()) {
        std::cerr << "Username: ";
        std::getline(std::cin, username);
        if (username.empty())
            throw std::invalid_argument("changepass: username is required");
    }

    const char* p1 = getpass("New password: ");
    if (!p1) throw std::runtime_error("changepass: failed to read password");
    std::string pw1(p1);

    const char* p2 = getpass("Confirm: ");
    if (!p2) throw std::runtime_error("changepass: failed to read password");
    std::string pw2(p2);

    if (pw1 != pw2)
        throw std::invalid_argument("changepass: passwords do not match");
    if (pw1.empty())
        throw std::invalid_argument("changepass: password must not be empty");

    std::string endpoint = "/users/" + username + "/password";
    client.post_json(endpoint, {{"password", pw1}});
    std::cout << "Password changed for " << username << ".\n";
}

} // namespace amanda
