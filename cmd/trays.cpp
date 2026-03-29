#include "cmd/commands.hpp"
#include "client/client.hpp"
#include "config/amanda_config.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>

using json = nlohmann::json;

namespace amanda {

// ---------------------------------------------------------------------------
// Helper: compact summary after keygen (no raw key material)
// ---------------------------------------------------------------------------
static void print_summary(const json& t) {
    std::cout << "Tray generated:\n"
              << "  alias:   " << t.value("alias",   "") << "\n"
              << "  profile: " << t.value("type",    "") << "\n"
              << "  id:      " << t.value("id",      "") << "\n"
              << "  created: " << t.value("created", std::string{}) << "\n"
              << "  expires: " << t.value("expires", std::string{}) << "\n";
    if (t.contains("slots")) {
        const auto& slots = t.at("slots");
        std::cout << "  slots:   " << slots.size() << "\n";
        for (const auto& s : slots) {
            std::string pk64 = s.value("pk_b64", "");
            // Compute byte size from base64 length, accounting for padding.
            size_t pk_bytes = (pk64.size() * 3) / 4;
            if (pk64.size() >= 1 && pk64.back() == '=') --pk_bytes;
            if (pk64.size() >= 2 && pk64[pk64.size() - 2] == '=') --pk_bytes;
            std::cout << "    - " << s.value("alg", "")
                      << "  pk=" << pk_bytes << "B"
                      << "  sk=" << (s.value("has_sk", false) ? "stored" : "none") << "\n";
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: pretty-print a tray JSON object
// ---------------------------------------------------------------------------
static void print_tray(const json& t, bool public_only = false) {
    std::cout << "id:      " << t.value("id",      "") << "\n";
    std::cout << "alias:   " << t.value("alias",   "") << "\n";
    std::cout << "type:    " << t.value("type",     "") << "\n";
    std::cout << "created: " << t.value("created", std::string{}) << "\n";
    std::cout << "expires: " << t.value("expires", std::string{}) << "\n";
    if (t.contains("slots")) {
        std::cout << "slots:\n";
        for (const auto& s : t.at("slots")) {
            std::cout << "  alg:    " << s.value("alg", "") << "\n";
            std::cout << "  pk_b64: " << s.value("pk_b64", "") << "\n";
            if (!public_only) {
                if (s.contains("has_sk"))
                    std::cout << "  has_sk: " << (s["has_sk"].get<bool>() ? "true" : "false") << "\n";
                if (s.contains("sk_b64"))
                    std::cout << "  sk_b64: " << s.value("sk_b64", "") << "\n";
            }
        }
    }
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------
// Usage: amanda keygen --alias <name> --profile <level> [--pg crystals]
// ---------------------------------------------------------------------------
void cmd_keygen(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    std::string alias;
    std::string tray_type = "level3";
    std::string profile_group;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--alias" && i + 1 < args.size()) {
            alias = args[++i];
        } else if (args[i] == "--profile" && i + 1 < args.size()) {
            tray_type = args[++i];
        } else if (args[i] == "--pg" && i + 1 < args.size()) {
            profile_group = args[++i];
        }
    }

    if (alias.empty())
        throw std::invalid_argument("keygen: --alias is required");
    if (!profile_group.empty() && profile_group != "crystals")
        throw std::invalid_argument("keygen: --pg must be 'crystals'");

    auto resp = client.post_json("/trays", {{"alias", alias}, {"type", tray_type}});
    print_summary(resp);
}

// ---------------------------------------------------------------------------
// trays
// ---------------------------------------------------------------------------
// Usage: amanda trays [-v]
// ---------------------------------------------------------------------------
void cmd_trays(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    bool verbose = false;
    for (const auto& a : args)
        if (a == "-v" || a == "--verbose") verbose = true;

    auto resp = client.get("/trays");
    if (!verbose) {
        for (const auto& a : resp.at("trays"))
            std::cout << a.get<std::string>() << "\n";
    } else {
        for (const auto& alias_j : resp.at("trays")) {
            std::string alias = alias_j.get<std::string>();
            try {
                auto t = client.get("/trays/" + alias);
                print_tray(t);
                std::cout << "\n";
            } catch (const std::exception& e) {
                std::cerr << "Error fetching " << alias << ": " << e.what() << "\n";
            }
        }
    }
}

// ---------------------------------------------------------------------------
// tray
// ---------------------------------------------------------------------------
// Usage: amanda tray --alias <name> [--public]
// ---------------------------------------------------------------------------
void cmd_tray(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    std::string alias;
    bool public_only = false;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--alias" && i + 1 < args.size()) {
            alias = args[++i];
        } else if (args[i] == "--public") {
            public_only = true;
        }
    }

    if (alias.empty())
        throw std::invalid_argument("tray: --alias is required");

    json t;
    try {
        t = client.get("/trays/" + alias);
    } catch (const std::exception& e) {
        // Non-admin accessing a PWENC-encrypted tray: server returns 403 "access denied".
        // Return silently with no output.
        if (std::string(e.what()) == "access denied") return;
        throw;
    }

    // Admin accessing a PWENC-encrypted tray: server signals {encrypted:true}.
    // Prompt for the admin password and decrypt via POST /trays/:alias/view.
    if (t.value("encrypted", false)) {
        const char* pw = getpass("Password: ");
        if (!pw) throw std::runtime_error("tray: password input failed");
        t = client.post_json("/trays/" + alias + "/view", {{"password", std::string(pw)}});
    }

    print_tray(t, public_only);
}

// ---------------------------------------------------------------------------
// export-tray
// ---------------------------------------------------------------------------
// Usage: amanda export-tray --alias <name> [--to-file <path>]
// ---------------------------------------------------------------------------
void cmd_export_tray(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    std::string alias;
    std::string to_file;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--alias" && i + 1 < args.size()) {
            alias = args[++i];
        } else if (args[i] == "--to-file" && i + 1 < args.size()) {
            to_file = args[++i];
        }
    }

    if (alias.empty())
        throw std::invalid_argument("export-tray: --alias is required");

    auto t = client.get("/trays/" + alias + "/export");
    std::string out = t.dump(2);

    if (!to_file.empty()) {
        std::ofstream f(to_file);
        if (!f.is_open())
            throw std::runtime_error("Cannot write to " + to_file);
        f << out << "\n";
        std::cout << "Tray exported to " << to_file << "\n";
    } else {
        std::cout << out << "\n";
    }
}

// ---------------------------------------------------------------------------
// mark-default
// ---------------------------------------------------------------------------
// Usage: amanda mark-default --alias <name>
// ---------------------------------------------------------------------------
void cmd_mark_default(HttpClient& /*client*/, AmandaConfig& cfg, const Args& args) {
    std::string alias;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--alias" && i + 1 < args.size())
            alias = args[++i];
    }
    if (alias.empty())
        throw std::invalid_argument("mark-default: --alias is required");
    cfg.default_tray = alias;
    save_config(cfg);
    std::cout << "Default tray set to '" << alias << "'\n";
}

} // namespace amanda
