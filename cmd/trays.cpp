#include "cmd/commands.hpp"
#include "client/client.hpp"
#include "config/amanda_config.hpp"

#include <crystals/crystals.hpp>
#include <nlohmann/json.hpp>
#include <openssl/ui.h>
#include <openssl/crypto.h>

#include <cmath>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using json = nlohmann::json;

// ── Password helpers (protect command) ────────────────────────────────────────

static bool pw_read_file(const std::string& path, char* buf, int buflen) {
    std::ifstream f(path);
    if (!f) {
        std::cerr << "Error: cannot open password file: " << path << "\n";
        return false;
    }
    std::string line;
    std::getline(f, line);
    size_t start = 0;
    while (start < line.size() && (line[start] == ' ' || line[start] == '\t' ||
                                    line[start] == '\r' || line[start] == '\n'))
        ++start;
    size_t end = line.size();
    while (end > start && (line[end-1] == ' ' || line[end-1] == '\t' ||
                            line[end-1] == '\r' || line[end-1] == '\n'))
        --end;
    std::string pw = line.substr(start, end - start);
    if ((int)pw.size() >= buflen) {
        std::cerr << "Error: password in file is too long\n";
        OPENSSL_cleanse(line.data(), line.size());
        OPENSSL_cleanse(pw.data(), pw.size());
        return false;
    }
    std::memcpy(buf, pw.data(), pw.size());
    buf[pw.size()] = '\0';
    OPENSSL_cleanse(line.data(), line.size());
    OPENSSL_cleanse(pw.data(), pw.size());
    return true;
}

static bool pw_prompt_confirm(char* buf, int buflen) {
    char verify[256] = {};
    if (buflen > (int)sizeof(verify)) buflen = (int)sizeof(verify);
    if (EVP_read_pw_string(buf, buflen, "Enter password: ", 0) != 0) return false;
    if (EVP_read_pw_string(verify, (int)sizeof(verify), "Confirm password: ", 0) != 0) {
        OPENSSL_cleanse(verify, sizeof(verify));
        return false;
    }
    bool match = (std::strcmp(buf, verify) == 0);
    OPENSSL_cleanse(verify, sizeof(verify));
    if (!match) std::cerr << "passwords do not match\n";
    return match;
}

static float pw_shannon_entropy(const std::string& s) {
    if (s.empty()) return 0.0f;
    int freq[256] = {};
    for (unsigned char c : s) freq[(int)c]++;
    float H = 0.0f;
    float n = (float)s.size();
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / n;
            H -= p * std::log2(p);
        }
    }
    return H;
}

// Throws std::invalid_argument if password is too short.
// Prints a warning (but does not throw) if entropy is low.
static void pw_check_strength(const char* buf) {
    size_t len = std::strlen(buf);
    if (len < 3)
        throw std::invalid_argument("password must be at least 3 characters");
    std::string s(buf, len);
    float bits = pw_shannon_entropy(s) * (float)len;
    if (bits < 80.0f)
        std::cerr << "Warning: password has low entropy (" << bits
                  << " bits); consider using a stronger password\n";
}

// Write raw YAML bytes to a short-lived temp file, load as a Tray, then unlink.
// The temp file never persists across this function's lifetime.
static Tray tray_from_yaml_bytes(const std::vector<uint8_t>& raw) {
    char tmppath[] = "/tmp/amanda-tray-XXXXXX";
    int fd = ::mkstemp(tmppath);
    if (fd < 0)
        throw std::runtime_error("failed to create temporary file for tray loading");
    ::fchmod(fd, 0600);
    ssize_t written = 0;
    while ((size_t)written < raw.size()) {
        ssize_t n = ::write(fd, raw.data() + written, raw.size() - (size_t)written);
        if (n < 0) {
            ::close(fd);
            ::unlink(tmppath);
            throw std::runtime_error("failed to write temporary tray file");
        }
        written += n;
    }
    ::close(fd);
    Tray tray;
    try {
        tray = load_tray_yaml(std::string(tmppath));
    } catch (...) {
        ::unlink(tmppath);
        throw;
    }
    ::unlink(tmppath);
    return tray;
}

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
    bool        protect = false;
    std::string pw_file;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--alias" && i + 1 < args.size()) {
            alias = args[++i];
        } else if (args[i] == "--to-file" && i + 1 < args.size()) {
            to_file = args[++i];
        } else if (args[i] == "--protect") {
            protect = true;
        } else if (args[i] == "--password-file" && i + 1 < args.size()) {
            pw_file = args[++i];
        }
    }

    if (alias.empty())
        throw std::invalid_argument("export-tray: --alias is required");
    if (!pw_file.empty() && !protect)
        throw std::invalid_argument("export-tray: --password-file requires --protect");

    std::string ct, etag;
    auto raw = client.get_binary("/trays/" + alias + "/export", ct, etag);
    std::string out(raw.begin(), raw.end());

    if (protect) {
        char pw_buf[256] = {};

        if (!pw_file.empty()) {
            if (!pw_read_file(pw_file, pw_buf, sizeof(pw_buf))) {
                OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
                throw std::runtime_error("export-tray: failed to read password file");
            }
        } else {
            if (!pw_prompt_confirm(pw_buf, sizeof(pw_buf))) {
                OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
                throw std::runtime_error("export-tray: password input failed");
            }
        }

        try {
            pw_check_strength(pw_buf);
        } catch (const std::invalid_argument& e) {
            OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
            throw std::invalid_argument(std::string("export-tray: ") + e.what());
        }

        Tray tray;
        try {
            tray = tray_from_yaml_bytes(raw);
        } catch (...) {
            OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
            throw;
        }

        SecureTray st;
        try {
            st = protect_tray(tray, pw_buf, std::strlen(pw_buf));
        } catch (const std::exception& e) {
            OPENSSL_cleanse(pw_buf, sizeof(pw_buf));
            throw std::runtime_error(std::string("export-tray: protect failed: ") + e.what());
        }
        OPENSSL_cleanse(pw_buf, sizeof(pw_buf));

        out = emit_secure_tray_yaml(st);
    }

    if (!to_file.empty()) {
        std::ofstream f(to_file);
        if (!f.is_open())
            throw std::runtime_error("Cannot write to " + to_file);
        f << out;
        std::cout << "Tray exported to " << to_file << "\n";
    } else {
        std::cout << out;
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
