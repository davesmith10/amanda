#include "config/amanda_config.hpp"
#include "client/client.hpp"
#include "cmd/commands.hpp"

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
        "\n"
        "Commands:\n"
        "  login      [--username <name>] [--token <base64>]\n"
        "  logout\n"
        "  newuser    --username <name> [--assert <scope> ...]\n"
        "  listuser\n"
        "  changepass [--username <name>]\n"
        "  keygen     --alias <name> [--tray <level>] [--pg crystals]\n"
        "  trays      [-v]\n"
        "  tray       --alias <name> [--public]\n"
        "  export-tray --alias <name> [--to-file <path>]\n"
        "  mark-default --alias <name>\n"
        "  create     <path> [--from-file <f>|--from-text <t>] [--mimetype <m>] [--tray <a>]\n"
        "  read       <path> [--to-file <path>]\n"
        "  meta       <path>\n"
        "  secrets    [--prefix <prefix>]\n"
        "  link       --target <path> --link <path>\n"
        "  health\n";
}

int main(int argc, char** argv) {
    std::string server_override;
    std::string cacert;
    bool insecure  = false;
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

        if      (command == "login")        amanda::cmd_login(client, cfg, cmd_args);
        else if (command == "logout")       amanda::cmd_logout(client, cfg, cmd_args);
        else if (command == "newuser")      amanda::cmd_newuser(client, cfg, cmd_args);
        else if (command == "listuser")     amanda::cmd_listuser(client, cfg, cmd_args);
        else if (command == "changepass")   amanda::cmd_changepass(client, cfg, cmd_args);
        else if (command == "keygen")       amanda::cmd_keygen(client, cfg, cmd_args);
        else if (command == "trays")        amanda::cmd_trays(client, cfg, cmd_args);
        else if (command == "tray")         amanda::cmd_tray(client, cfg, cmd_args);
        else if (command == "export-tray")  amanda::cmd_export_tray(client, cfg, cmd_args);
        else if (command == "mark-default") amanda::cmd_mark_default(client, cfg, cmd_args);
        else if (command == "create")       amanda::cmd_create(client, cfg, cmd_args);
        else if (command == "read")         amanda::cmd_read(client, cfg, cmd_args);
        else if (command == "meta")         amanda::cmd_meta(client, cfg, cmd_args);
        else if (command == "secrets")      amanda::cmd_secrets(client, cfg, cmd_args);
        else if (command == "link")         amanda::cmd_link(client, cfg, cmd_args);
        else if (command == "health")       amanda::cmd_health(client, cfg, cmd_args);
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
