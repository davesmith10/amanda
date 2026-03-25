#include "cmd/commands.hpp"
#include "client/client.hpp"
#include "config/amanda_config.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <string>

namespace amanda {

// ---------------------------------------------------------------------------
// util:cacert — trace CA certificate configuration and check paths
// ---------------------------------------------------------------------------
void cmd_util_cacert(HttpClient& /*client*/, AmandaConfig& cfg, const Args& args) {
    // The --cacert flag (if supplied) has already been merged into cfg.cacert
    // by main.cpp before this function is called.  We also receive the raw
    // args so we can distinguish "came from flag" vs "came from config file".

    // Determine whether the value was supplied on the command line.
    // main.cpp merges --cacert into cfg.cacert, so we detect it by checking
    // whether any element of args looks like it was a --cacert flag (it won't
    // be — args only contains arguments AFTER the command name).  Instead we
    // re-read the config to compare: if cfg.cacert differs from the file value
    // it must have come from the flag.
    AmandaConfig file_cfg = load_config();
    bool from_flag   = (!cfg.cacert.empty() && cfg.cacert != file_cfg.cacert);
    bool from_config = (!file_cfg.cacert.empty());

    auto check_path = [](const std::string& path) {
        struct stat st{};
        if (::stat(path.c_str(), &st) != 0) {
            std::cout << "  path exists : NO  (stat failed: file not found or not accessible)\n";
            return;
        }
        std::cout << "  path exists : YES\n";
        if (S_ISREG(st.st_mode))
            std::cout << "  type        : regular file\n";
        else if (S_ISDIR(st.st_mode))
            std::cout << "  type        : directory\n";
        else
            std::cout << "  type        : other (not a regular file)\n";
        if (::access(path.c_str(), R_OK) == 0)
            std::cout << "  readable    : YES\n";
        else
            std::cout << "  readable    : NO  (permission denied)\n";
    };

    std::cout << "=== cacert diagnostic ===\n\n";

    // ── Step 1: --cacert flag ───────────────────────────────────────────────
    std::cout << "1. --cacert flag\n";
    if (from_flag) {
        std::cout << "  set         : YES  (\"" << cfg.cacert << "\")\n";
        check_path(cfg.cacert);
        std::cout << "\n  -> This value will be used (flag overrides config file).\n";
    } else {
        std::cout << "  set         : NO\n";
    }

    // ── Step 2: ~/.sarekrc ──────────────────────────────────────────────────
    std::cout << "\n2. cacert in ~/.sarekrc\n";
    const char* home = std::getenv("HOME");
    std::string rc_path = home ? std::string(home) + "/.sarekrc" : "(HOME not set)";
    std::cout << "  config file : " << rc_path << "\n";
    if (from_config) {
        std::cout << "  cacert value: \"" << file_cfg.cacert << "\"\n";
        check_path(file_cfg.cacert);
        if (!from_flag)
            std::cout << "\n  -> This value will be used (no flag override).\n";
        else
            std::cout << "\n  -> Ignored (--cacert flag takes precedence).\n";
    } else {
        std::cout << "  cacert value: (not set)\n";
    }

    // ── Step 3: effective value summary ────────────────────────────────────
    std::cout << "\n3. Effective cacert for this session\n";
    if (!cfg.cacert.empty()) {
        std::cout << "  value       : \"" << cfg.cacert << "\"\n";
        std::cout << "  source      : " << (from_flag ? "--cacert flag" : "~/.sarekrc") << "\n";
    } else {
        std::cout << "  value       : (none)\n";
        std::cout << "  -> amanda will use the system CA bundle for TLS verification.\n";
        std::cout << "  -> For self-signed server certs, use --insecure or set cacert.\n";
    }

    // suppress unused-parameter warning
    (void)args;
}

} // namespace amanda
