#include "cmd/commands.hpp"
#include "client/client.hpp"
#include "config/amanda_config.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using json = nlohmann::json;

namespace amanda {

// ---------------------------------------------------------------------------
// MIME type lookup by file extension
// ---------------------------------------------------------------------------
static std::string mime_from_extension(const std::string& filename) {
    static const std::unordered_map<std::string, std::string> table = {
        {".txt",  "text/plain"},
        {".html", "text/html"},
        {".htm",  "text/html"},
        {".json", "application/json"},
        {".xml",  "application/xml"},
        {".yaml", "application/x-yaml"},
        {".yml",  "application/x-yaml"},
        {".png",  "image/png"},
        {".jpg",  "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".gif",  "image/gif"},
        {".pdf",  "application/pdf"},
        {".bin",  "application/octet-stream"},
        {".zip",  "application/zip"},
        {".gz",   "application/gzip"},
        {".pem",  "application/x-pem-file"},
        {".key",  "application/octet-stream"},
        {".crt",  "application/x-x509-ca-cert"},
    };
    auto dot = filename.rfind('.');
    if (dot == std::string::npos) return "application/octet-stream";
    std::string ext = filename.substr(dot);
    auto it = table.find(ext);
    return (it != table.end()) ? it->second : "application/octet-stream";
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------
// Usage:
//   amanda create <path> --from-file <file> | --from-text <text> | (stdin)
//                [--mimetype <type>] [--tray <alias>]
// ---------------------------------------------------------------------------
void cmd_create(HttpClient& client, AmandaConfig& cfg, const Args& args) {
    std::string path;
    std::string from_file;
    std::string from_text;
    std::string mimetype;
    std::string tray_alias = cfg.default_tray.empty() ? "system-token" : cfg.default_tray;

    // First non-flag arg is the path
    bool path_set = false;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--from-file" && i + 1 < args.size()) {
            from_file = args[++i];
        } else if (args[i] == "--from-text" && i + 1 < args.size()) {
            from_text = args[++i];
        } else if (args[i] == "--mimetype" && i + 1 < args.size()) {
            mimetype = args[++i];
        } else if (args[i] == "--tray" && i + 1 < args.size()) {
            tray_alias = args[++i];
        } else if (!path_set && args[i][0] != '-') {
            path = args[i];
            path_set = true;
        }
    }

    if (path.empty())
        throw std::invalid_argument("create: vault path is required");

    std::vector<uint8_t> data;

    if (!from_file.empty()) {
        std::ifstream f(from_file, std::ios::binary);
        if (!f.is_open())
            throw std::runtime_error("Cannot open file: " + from_file);
        data.assign((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
        if (mimetype.empty())
            mimetype = mime_from_extension(from_file);
    } else if (!from_text.empty()) {
        data.assign(from_text.begin(), from_text.end());
        if (mimetype.empty()) mimetype = "text/plain";
    } else {
        // Read from stdin
        data.assign((std::istreambuf_iterator<char>(std::cin)),
                     std::istreambuf_iterator<char>());
        if (mimetype.empty()) mimetype = "application/octet-stream";
    }

    std::string endpoint = "/secrets" + path + "?tray=" + tray_alias;
    client.post_binary(endpoint, data, mimetype);
    std::cout << "Created " << path << "\n";
}

// ---------------------------------------------------------------------------
// read
// ---------------------------------------------------------------------------
// Usage: amanda read <path> [--to-file <file>]
// ---------------------------------------------------------------------------
void cmd_read(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    std::string path;
    std::string to_file;
    bool path_set = false;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--to-file" && i + 1 < args.size()) {
            to_file = args[++i];
        } else if (!path_set && args[i][0] != '-') {
            path = args[i];
            path_set = true;
        }
    }

    if (path.empty())
        throw std::invalid_argument("read: vault path is required");

    std::string ct;
    auto data = client.get_binary("/secrets" + path, ct);

    if (!to_file.empty()) {
        std::ofstream f(to_file, std::ios::binary);
        if (!f.is_open())
            throw std::runtime_error("Cannot write to " + to_file);
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
    } else {
        std::cout.write(reinterpret_cast<const char*>(data.data()),
                        static_cast<std::streamsize>(data.size()));
    }
}

// ---------------------------------------------------------------------------
// meta
// ---------------------------------------------------------------------------
// Usage: amanda meta <path>
// ---------------------------------------------------------------------------
void cmd_meta(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    std::string path;
    for (const auto& a : args)
        if (a[0] != '-' && path.empty()) path = a;

    if (path.empty())
        throw std::invalid_argument("meta: vault path is required");

    auto m = client.get("/secrets" + path + "/meta");
    std::cout << "path:      " << path                       << "\n";
    std::cout << "object_id: " << m.value("object_id",  0)   << "\n";
    std::cout << "created:   " << m.value("created",    0)   << "\n";
    std::cout << "size:      " << m.value("size",        0)   << "\n";
    std::cout << "mimetype:  " << m.value("mimetype",   "") << "\n";
    std::cout << "tray_id:   " << m.value("tray_id",    "") << "\n";
    if (m.contains("link_path"))
        std::cout << "link_path: " << m["link_path"].get<std::string>() << "\n";
}

// ---------------------------------------------------------------------------
// secrets
// ---------------------------------------------------------------------------
// Usage: amanda secrets [--prefix <prefix>]
// ---------------------------------------------------------------------------
void cmd_secrets(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    std::string prefix;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--prefix" && i + 1 < args.size())
            prefix = args[++i];
    }

    std::string endpoint = "/secrets";
    if (!prefix.empty()) endpoint += "?prefix=" + prefix;

    auto resp = client.get(endpoint);
    for (const auto& p : resp.at("secrets"))
        std::cout << p.get<std::string>() << "\n";
}

// ---------------------------------------------------------------------------
// link
// ---------------------------------------------------------------------------
// Usage: amanda link --target <path> --link <path>
// ---------------------------------------------------------------------------
void cmd_link(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    std::string target;
    std::string link;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--target" && i + 1 < args.size()) {
            target = args[++i];
        } else if (args[i] == "--link" && i + 1 < args.size()) {
            link = args[++i];
        }
    }

    if (target.empty()) throw std::invalid_argument("link: --target is required");
    if (link.empty())   throw std::invalid_argument("link: --link is required");

    client.post_json("/links", {{"target", target}, {"link", link}});
    std::cout << "Link " << link << " -> " << target << " created\n";
}

// ---------------------------------------------------------------------------
// health (convenience, no auth required)
// ---------------------------------------------------------------------------
void cmd_health(HttpClient& client, AmandaConfig& /*cfg*/, const Args& /*args*/) {
    auto resp = client.get("/health");
    std::cout << resp.value("status", "unknown") << "\n";
}

} // namespace amanda
