#include "config/amanda_config.hpp"
#include "client/client.hpp"
#include "cmd/commands.hpp"
#include "cmd/curl_emitter.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static void usage() {
    std::cerr <<
        "Usage: amanda [--server <url>] [--insecure | --cacert <pem>] <command> [args...]\n"
        "\n"
        "Global options:\n"
        "  --server <url>     Override server URL from ~/.sarekrc\n"
        "  --cacert <path>    PEM file to trust for server certificate verification\n"
        "  --insecure         Skip TLS certificate verification entirely (dev only)\n"
        "  --curl             Emit equivalent curl command(s) instead of executing\n"
        "\n"
        "Identity:\n"
        "  login        [--username <name>] [--registration-token <base64>] [--password-file <path>]\n"
        "  login-status Check local token validity and expiry (no server contact)\n"
        "  logout\n"
        "  whoami       [--verbose|-v]\n"
        "  list-users\n"
        "  change-pw    [--username <name>]\n"
        "\n"
        "Trays:\n"
        "  keygen       --alias <name> [--profile <level>] [--pg crystals]\n"
        "  trays\n"
        "  export-tray  --alias <name> [--to-file <path>] [--protect [--password-file <path>]]\n"
        "  mark-default  --alias <name>\n"
        "  clear-default\n"
        "\n"
        "Secrets:\n"
        "  put          <path> [--from-file <f>|--from-text <t>] [--mimetype <m>] [--tray <a>]\n"
        "  get          <path> [--to-file <path>]\n"
        "  edit         <path>\n"
        "  meta         <path>\n"
        "  list         [--prefix <prefix>]\n"
        "  link         <target-path> <v-path>\n"
        "  unlink       <v-path>\n"
        "\n"
        "Misc:\n"
        "  health\n"
        "  yaml-extract <path> <ypath>\n"
        "  json-extract <path> <json-pointer>\n"
        "  regex-extract <path> <pattern> [--mode ecmascript|basic|extended]\n"
        "\n"
        "Utilities:\n"
        "  bearer-token [--ttl <number>[s|m|h|d]] [--assert <scope> ...]\n"
        "  util-cacert  Trace CA certificate configuration and check paths\n"
        "  wrap         [--ttl <number>[s|m|h|d]]   (reads from stdin)\n"
        "\n"
        "OAuth:\n"
        "  login-oauth  [--client-id <id>] [--ttl <number>[s|m|h|d]]\n"
        "\n"
        "Admin:\n"
        "  newuser      --username <name> [--assert <scope> ...]\n"
        "  deluser      --username <name>\n"
        "  flush-all\n"
        "  list-tokens\n"
        "  revoke-token <token_id>\n"
        "  revoke-tokens <username>\n"
        "  revoke-all\n"
        "  oauth-setup  --username <name> [--save]\n"
        "  oauth-revoke --username <name>\n";
}

int main(int argc, char** argv) {
    std::string server_override;
    std::string cacert;
    bool insecure  = false;
    bool curl_mode = false;
    std::string command;
    amanda::Args cmd_args;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--server" && i + 1 < argc) {
            server_override = argv[++i];
        } else if (arg == "--cacert" && i + 1 < argc) {
            cacert = argv[++i];
        } else if (arg == "--insecure") {
            insecure = true;
        } else if (arg == "--curl") {
            curl_mode = true;
        } else if (command.empty()) {
            command = arg;
        } else {
            cmd_args.push_back(arg);
        }
    }

    if (command.empty() || command == "--help" || command == "-h") {
        usage();
        return 0;
    }

    try {
        amanda::AmandaConfig cfg = amanda::load_config();
        if (!server_override.empty())
            cfg.server_url = server_override;
        // Command-line --cacert overrides config file value
        if (!cacert.empty())
            cfg.cacert = cacert;

        amanda::HttpClient client(cfg, insecure, cfg.cacert);

        if (curl_mode) {
            std::string tok = client.has_oauth_token() ? client.oauth_bearer()
                            : client.has_token()        ? client.token_b64()
                            : "";
            amanda::CurlEmitter emitter(cfg, insecure, tok);

            if      (command == "login")      emitter.emit_login(cmd_args);
            else if (command == "logout")     emitter.emit_logout(cmd_args);
            else if (command == "put")        emitter.emit_put(cmd_args);
            else if (command == "get")        emitter.emit_get(cmd_args);
            else if (command == "meta")       emitter.emit_meta(cmd_args);
            else if (command == "list")       emitter.emit_list(cmd_args);
            else if (command == "link")       emitter.emit_link(cmd_args);
            else if (command == "health")     emitter.emit_health(cmd_args);
            else if (command == "keygen")     emitter.emit_keygen(cmd_args);
            else if (command == "trays")      emitter.emit_trays(cmd_args);
            else if (command == "wrap")       emitter.emit_wrap(cmd_args);
            else if (command == "newuser")    emitter.emit_newuser(cmd_args);
            else if (command == "list-users") emitter.emit_listuser(cmd_args);
            else if (command == "change-pw")  emitter.emit_changepass(cmd_args);
            else {
                std::cerr << "amanda: --curl not supported for command '" << command << "'\n";
                return 1;
            }
            return 0;
        }

        if      (command == "login")         amanda::cmd_login(client, cfg, cmd_args);
        else if (command == "login-status")  amanda::cmd_login_status(client, cfg, cmd_args);
        else if (command == "logout")        amanda::cmd_logout(client, cfg, cmd_args);
        else if (command == "whoami")       amanda::cmd_whoami(client, cfg, cmd_args);
        else if (command == "newuser")      amanda::cmd_newuser(client, cfg, cmd_args);
        else if (command == "list-users")   amanda::cmd_listuser(client, cfg, cmd_args);
        else if (command == "change-pw")    amanda::cmd_changepass(client, cfg, cmd_args);
        else if (command == "deluser")      amanda::cmd_deluser(client, cfg, cmd_args);
        else if (command == "flush-all")    amanda::cmd_flush_all(client, cfg, cmd_args);
        else if (command == "keygen")       amanda::cmd_keygen(client, cfg, cmd_args);
        else if (command == "trays")        amanda::cmd_trays(client, cfg, cmd_args);
        else if (command == "export-tray")  amanda::cmd_export_tray(client, cfg, cmd_args);
        else if (command == "mark-default")  amanda::cmd_mark_default(client, cfg, cmd_args);
        else if (command == "clear-default") amanda::cmd_clear_default(client, cfg, cmd_args);
        else if (command == "put")          amanda::cmd_create(client, cfg, cmd_args);
        else if (command == "get")          amanda::cmd_read(client, cfg, cmd_args);
        else if (command == "edit")         amanda::cmd_edit(client, cfg, cmd_args);
        else if (command == "meta")         amanda::cmd_meta(client, cfg, cmd_args);
        else if (command == "list")         amanda::cmd_secrets(client, cfg, cmd_args);
        else if (command == "link")         amanda::cmd_link(client, cfg, cmd_args);
        else if (command == "unlink")       amanda::cmd_unlink(client, cfg, cmd_args);
        else if (command == "health")        amanda::cmd_health(client, cfg, cmd_args);
        else if (command == "yaml-extract")  amanda::cmd_yaml_extract(client, cfg, cmd_args);
        else if (command == "json-extract")  amanda::cmd_json_extract(client, cfg, cmd_args);
        else if (command == "regex-extract") amanda::cmd_regex_extract(client, cfg, cmd_args);
        else if (command == "list-tokens")   amanda::cmd_list_tokens(client, cfg, cmd_args);
        else if (command == "revoke-token")  amanda::cmd_revoke_token(client, cfg, cmd_args);
        else if (command == "revoke-tokens") amanda::cmd_revoke_tokens(client, cfg, cmd_args);
        else if (command == "revoke-all")    amanda::cmd_revoke_all(client, cfg, cmd_args);
        else if (command == "oauth-setup")   amanda::cmd_oauth_setup(client, cfg, cmd_args);
        else if (command == "oauth-revoke")  amanda::cmd_oauth_revoke(client, cfg, cmd_args);
        else if (command == "login-oauth")   amanda::cmd_login_oauth(client, cfg, cmd_args);
        else if (command == "wrap")          amanda::cmd_wrap(client, cfg, cmd_args);
        else if (command == "bearer-token")  amanda::cmd_bearer_token(client, cfg, cmd_args);
        else if (command == "util-cacert")   amanda::cmd_util_cacert(client, cfg, cmd_args);
        else {
            std::cerr << "amanda: unknown command '" << command << "'\n";
            usage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "amanda: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
