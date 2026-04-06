#include "config/amanda_config.hpp"

#include <yaml-cpp/yaml.h>

#include <cstdlib>
#include <fstream>
#include <stdexcept>

namespace amanda {

static std::string expand_tilde(const std::string& path) {
    if (path.empty() || path[0] != '~') return path;
    const char* home = std::getenv("HOME");
    if (!home) return path;
    return std::string(home) + path.substr(1);
}

static std::string sarekrc_path() {
    const char* home = std::getenv("HOME");
    if (!home) throw std::runtime_error("HOME environment variable not set");
    return std::string(home) + "/.sarekrc";
}

AmandaConfig load_config() {
    AmandaConfig cfg;
    cfg.server_url   = "https://localhost:8443";
    cfg.default_tray = "";

    std::string path = sarekrc_path();
    std::ifstream f(path);
    if (!f.is_open()) return cfg;

    YAML::Node y = YAML::Load(f);
    if (y["server"])       cfg.server_url   = y["server"].as<std::string>();
    if (y["default_tray"]) cfg.default_tray = y["default_tray"].as<std::string>();
    if (y["cacert"])       cfg.cacert       = expand_tilde(y["cacert"].as<std::string>());
    if (y["username"])     cfg.username     = y["username"].as<std::string>();
    if (y["oauth_client_id"]) cfg.oauth_client_id = y["oauth_client_id"].as<std::string>();
    return cfg;
}

void save_config(const AmandaConfig& cfg) {
    std::string path = sarekrc_path();
    std::ofstream f(path);
    if (!f.is_open())
        throw std::runtime_error("Cannot write config to " + path);
    f << "server: " << cfg.server_url << "\n";
    f << "default_tray: " << cfg.default_tray << "\n";
    if (!cfg.cacert.empty())
        f << "cacert: " << cfg.cacert << "\n";
    if (!cfg.username.empty())
        f << "username: " << cfg.username << "\n";
    if (!cfg.oauth_client_id.empty())
        f << "oauth_client_id: " << cfg.oauth_client_id << "\n";
}

} // namespace amanda
