#include "cmd/commands.hpp"
#include "client/client.hpp"

#include <crystals/crystals.hpp>

#include <unistd.h>   // getpass

#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace amanda {

// ---------------------------------------------------------------------------
// Helper: read a password from a file (strips trailing newline / \r\n).
// ---------------------------------------------------------------------------
static std::string read_password_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open --password-file: " + path);
    std::string pw;
    std::getline(f, pw);
    if (!pw.empty() && pw.back() == '\r') pw.pop_back();
    if (pw.empty()) throw std::runtime_error("--password-file is empty");
    return pw;
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------
// Usage:
//   amanda login [--username <name>] [--password-file <path>]
//   amanda login --token <base64> [--password-file <path>]   (invite flow)
// ---------------------------------------------------------------------------
void cmd_login(HttpClient& client, AmandaConfig& cfg, const Args& args) {
    std::string username;
    std::string token_arg;
    std::string password_file;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--username" && i + 1 < args.size()) {
            username = args[++i];
        } else if (args[i] == "--token" && i + 1 < args.size()) {
            token_arg = args[++i];
        } else if (args[i] == "--password-file" && i + 1 < args.size()) {
            password_file = args[++i];
        }
    }

    if (!token_arg.empty()) {
        // Invite flow: decode token, save it, then set password
        auto wire = base64_decode(token_arg);
        client.save_token(wire);

        std::string p1, p2;
        if (!password_file.empty()) {
            p1 = read_password_file(password_file);
            p2 = p1;
        } else {
            p1 = getpass("Set password: ");
            p2 = getpass("Confirm password: ");
        }
        if (p1 != p2)
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
    std::string password = password_file.empty()
        ? std::string(getpass("Password: "))
        : read_password_file(password_file);

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
// --verbose: also hex-dumps the raw token bytes.
// ---------------------------------------------------------------------------
void cmd_whoami(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    bool verbose = false;
    for (const auto& a : args)
        if (a == "--verbose" || a == "-v") verbose = true;

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

    // Format token_uuid as "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    const uint8_t* u = tok.token_uuid;
    char uuid_str[37];
    std::snprintf(uuid_str, sizeof(uuid_str),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        u[0],u[1],u[2],u[3], u[4],u[5], u[6],u[7],
        u[8],u[9], u[10],u[11],u[12],u[13],u[14],u[15]);

    std::cout << username << "\n";
    std::cout << "token-id: " << uuid_str << "\n";

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

    if (verbose) {
        std::cout << "\ntoken (" << wire.size() << " bytes):\n";
        const size_t row = 16;
        for (size_t off = 0; off < wire.size(); off += row) {
            // Offset
            char obuf[8];
            std::snprintf(obuf, sizeof(obuf), "%06zx", off);
            std::cout << obuf << "  ";
            // Hex
            for (size_t i = 0; i < row; ++i) {
                if (off + i < wire.size()) {
                    char hbuf[3];
                    std::snprintf(hbuf, sizeof(hbuf), "%02x", wire[off + i]);
                    std::cout << hbuf;
                } else {
                    std::cout << "  ";
                }
                std::cout << (i == 7 ? "  " : " ");
            }
            std::cout << " |";
            // ASCII
            for (size_t i = 0; i < row && off + i < wire.size(); ++i) {
                uint8_t c = wire[off + i];
                std::cout << (char)(c >= 0x20 && c < 0x7f ? c : '.');
            }
            std::cout << "|\n";
        }
    }
}

// ---------------------------------------------------------------------------
// login:status
// ---------------------------------------------------------------------------
// Reads the local token and prints its validity without contacting the server.
// ---------------------------------------------------------------------------
void cmd_login_status(HttpClient& client, AmandaConfig& /*cfg*/, const Args& /*args*/) {
    if (!client.has_token()) {
        std::cout << "not logged in\n";
        return;
    }

    auto wire = base64_decode(client.token_b64());
    Token tok = token_unpack(wire);

    int64_t now     = static_cast<int64_t>(std::time(nullptr));
    int64_t secs_left = tok.expires_at - now;

    if (secs_left <= 0) {
        std::cout << "expired, please login.\n";
        return;
    }

    // Extract username and assertions
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

    // Format expiry timestamp
    std::time_t exp_t = static_cast<std::time_t>(tok.expires_at);
    char time_buf[64];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&exp_t));

    // Format time remaining as Xd Xh Xm Xs
    int64_t d = secs_left / 86400;
    int64_t h = (secs_left % 86400) / 3600;
    int64_t m = (secs_left % 3600)  / 60;
    int64_t s = secs_left % 60;
    std::ostringstream ttl;
    if (d) ttl << d << "d ";
    if (d || h) ttl << h << "h ";
    if (d || h || m) ttl << m << "m ";
    ttl << s << "s";

    std::cout << "logged in as : " << username << "\n";
    std::cout << "expires      : " << time_buf << "  (in " << ttl.str() << ")\n";
    if (!assertions.empty()) {
        std::cout << "scope        :";
        for (const auto& a : assertions)
            std::cout << "  " << a;
        std::cout << "\n";
    }
}

} // namespace amanda
