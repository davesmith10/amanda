#pragma once

#include "config/amanda_config.hpp"

#include <string>
#include <vector>

namespace amanda {

class HttpClient;

// Each command receives the HTTP client, the (possibly modified) config, and
// the remaining command-line arguments after the command name.
using Args = std::vector<std::string>;

void cmd_login      (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_logout     (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_whoami     (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_newuser    (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_listuser   (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_changepass (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_deluser    (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_flush_all  (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_keygen     (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_trays      (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_tray       (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_export_tray(HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_mark_default(HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_create     (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_read       (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_meta       (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_secrets    (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_link         (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_health       (HttpClient& client, AmandaConfig& cfg, const Args& args);
void cmd_yaml_extract (HttpClient& client, AmandaConfig& cfg, const Args& args);

} // namespace amanda
