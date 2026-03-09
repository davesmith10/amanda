#pragma once

#include <string>

namespace amanda {

struct AmandaConfig {
    std::string server_url;     // e.g. "https://localhost:8443"
    std::string default_tray;   // alias used by create command
    std::string cacert;         // path to PEM CA cert for server verification
    std::string username;       // default username for login
};

// Load $HOME/.sarekrc. Returns defaults if file doesn't exist.
AmandaConfig load_config();

// Persist config back to $HOME/.sarekrc.
void save_config(const AmandaConfig& cfg);

} // namespace amanda
