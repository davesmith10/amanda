#include "cmd/commands.hpp"
#include "client/client.hpp"
#include "config/amanda_config.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <cstdio>
#include <ctime>
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
    std::string tray_alias = cfg.default_tray.empty() ? "system" : cfg.default_tray;

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
    std::string etag_unused;
    auto data = client.get_binary("/secrets" + path, ct, etag_unused);

    if (!to_file.empty()) {
        std::ofstream f(to_file, std::ios::binary);
        if (!f.is_open())
            throw std::runtime_error("Cannot write to " + to_file);
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
    } else {
        std::cout.write(reinterpret_cast<const char*>(data.data()),
                        static_cast<std::streamsize>(data.size()));
        if (data.empty() || data.back() != '\n')
            std::cout << '\n';
        std::cout.flush();
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
    std::cout << "object_id: " << m.value("object_id",  uint64_t{0}) << "\n";
    {
        int64_t ts = m.value("created", int64_t{0});
        char buf[64] = {};
        time_t t = static_cast<time_t>(ts);
        struct tm* gmt = gmtime(&t);
        strftime(buf, sizeof(buf), "%A, %-d %B %Y at %-H:%M:%S (GMT)", gmt);
        std::cout << "created:   " << ts << "/" << buf << "\n";
    }
    std::cout << "size:      " << m.value("size",        uint64_t{0}) << "\n";
    std::cout << "mimetype:  " << m.value("mimetype",   "") << "\n";
    {
        std::string tid   = m.value("tray_id",    "");
        std::string talias = m.value("tray_alias", "");
        std::cout << "tray_id:   " << tid;
        if (!talias.empty()) std::cout << " (" << talias << ")";
        std::cout << "\n";
    }
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
    for (const auto& entry : resp.at("secrets")) {
        bool is_link = entry.value("is_link", false);
        std::cout << (is_link ? "* " : "  ") << entry.at("path").get<std::string>() << "\n";
    }
}

// ---------------------------------------------------------------------------
// link
// ---------------------------------------------------------------------------
// Usage: amanda link <target-path> <v-path>
// ---------------------------------------------------------------------------
void cmd_link(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    if (args.size() < 2)
        throw std::invalid_argument("usage: link <target-path> <v-path>");

    const std::string& target = args[0];
    const std::string& link   = args[1];

    if (target.empty() || target[0] != '/')
        throw std::invalid_argument("link: target-path must start with '/'");
    if (link.empty() || link[0] != '/')
        throw std::invalid_argument("link: v-path must start with '/'");

    client.post_json("/links", {{"target", target}, {"link", link}});
    std::cout << "Link " << link << " -> " << target << " created\n";
}

// ---------------------------------------------------------------------------
// unlink
// ---------------------------------------------------------------------------
// Usage: amanda unlink <v-path>
// ---------------------------------------------------------------------------
void cmd_unlink(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    if (args.empty())
        throw std::invalid_argument("usage: unlink <v-path>");

    const std::string& path = args[0];

    if (path.empty() || path[0] != '/')
        throw std::invalid_argument("unlink: path must start with '/'");

    client.delete_("/links" + path);
    std::cout << "Unlinked " << path << "\n";
}

// ---------------------------------------------------------------------------
// health (convenience, no auth required)
// ---------------------------------------------------------------------------
void cmd_health(HttpClient& client, AmandaConfig& /*cfg*/, const Args& /*args*/) {
    auto resp = client.get("/health");
    std::cout << resp.value("status", "unknown") << "\n";
}

// ---------------------------------------------------------------------------
// yaml-extract
// ---------------------------------------------------------------------------
// Usage: amanda yaml-extract <vpath> <ypath-expression>
// ---------------------------------------------------------------------------
void cmd_yaml_extract(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    if (args.size() < 2)
        throw std::invalid_argument("yaml-extract: usage: yaml-extract <vpath> <ypath>");

    std::string vpath = args[0];
    std::string ypath = args[1];

    // Percent-encode the ypath for use as a query parameter value
    std::string ypath_enc;
    for (unsigned char c : ypath) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            ypath_enc += static_cast<char>(c);
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", c);
            ypath_enc += buf;
        }
    }

    std::string endpoint = "/secrets" + vpath + "/yaml-extract?ypath=" + ypath_enc;
    std::string ct;
    std::string etag_unused;
    auto data = client.get_binary(endpoint, ct, etag_unused);
    std::cout.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size()));
    std::cout << "\n";
}

// ---------------------------------------------------------------------------
// json-extract
// ---------------------------------------------------------------------------
// Usage: amanda json-extract <vpath> <json-pointer>
// ---------------------------------------------------------------------------
void cmd_json_extract(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    if (args.size() < 2)
        throw std::invalid_argument("json-extract: usage: json-extract <vpath> <json-pointer>");

    std::string vpath = args[0];
    std::string jptr  = args[1];

    // Percent-encode the JSON Pointer for use as a query parameter value
    std::string jptr_enc;
    for (unsigned char c : jptr) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            jptr_enc += static_cast<char>(c);
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", c);
            jptr_enc += buf;
        }
    }

    std::string endpoint = "/secrets" + vpath + "/json-extract?jptr=" + jptr_enc;
    std::string ct;
    std::string etag_unused;
    auto data = client.get_binary(endpoint, ct, etag_unused);
    std::cout.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size()));
    std::cout << "\n";
}

// ---------------------------------------------------------------------------
// regex-extract
// ---------------------------------------------------------------------------
// Usage: amanda regex-extract <vpath> <pattern> [--mode ecmascript|basic|extended]
// ---------------------------------------------------------------------------
void cmd_regex_extract(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    if (args.size() < 2)
        throw std::invalid_argument(
            "regex-extract: usage: regex-extract <vpath> <pattern> [--mode ecmascript|basic|extended]");

    std::string vpath   = args[0];
    std::string pattern = args[1];
    std::string mode;

    // Parse optional --mode flag
    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--mode" && i + 1 < args.size()) {
            mode = args[++i];
        } else if (args[i].rfind("--", 0) == 0) {
            throw std::invalid_argument(
                "regex-extract: unknown flag '" + args[i] + "'");
        }
    }

    // Percent-encode for use as a query parameter value
    auto pct_encode = [](const std::string& s) {
        std::string out;
        for (unsigned char c : s) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                out += static_cast<char>(c);
            } else {
                char buf[4];
                std::snprintf(buf, sizeof(buf), "%%%02X", c);
                out += buf;
            }
        }
        return out;
    };

    std::string endpoint = "/secrets" + vpath + "/regex-extract?pattern=" + pct_encode(pattern);
    if (!mode.empty())
        endpoint += "&mode=" + pct_encode(mode);

    std::string ct;
    std::string etag_unused;
    auto data = client.get_binary(endpoint, ct, etag_unused);
    std::cout.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size()));
    std::cout << "\n";
}

// ---------------------------------------------------------------------------
// wrap
// ---------------------------------------------------------------------------
// Usage: amanda wrap [--ttl <number>[s|m|h|d]]
// Reads plaintext from stdin; prints the wrapping token to stdout.
// ---------------------------------------------------------------------------

static int64_t parse_ttl_str(const std::string& s) {
    if (s.empty()) return 0;
    char unit = s.back();
    int64_t n = 0;
    if (std::isdigit(static_cast<unsigned char>(unit))) {
        n = std::stoll(s);
        return n;
    }
    n = std::stoll(std::string(s.begin(), s.end() - 1));
    switch (std::tolower(static_cast<unsigned char>(unit))) {
        case 's': return n;
        case 'm': return n * 60;
        case 'h': return n * 3600;
        case 'd': return n * 86400;
        default:  throw std::invalid_argument("wrap: unknown TTL unit '" + std::string(1, unit) + "'");
    }
}

void cmd_wrap(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    std::string ttl_str = "3600";

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--ttl" && i + 1 < args.size())
            ttl_str = args[++i];
    }

    int64_t ttl_secs = parse_ttl_str(ttl_str);
    if (ttl_secs < 600 || ttl_secs > 432000)
        throw std::invalid_argument("wrap: ttl must be 600-432000 seconds (10m-5d)");

    std::vector<uint8_t> plaintext(
        std::istreambuf_iterator<char>(std::cin),
        std::istreambuf_iterator<char>());
    if (plaintext.empty())
        throw std::invalid_argument("wrap: no data on stdin");

    std::string endpoint = "/wrap?ttl=" + std::to_string(ttl_secs);
    auto body = client.post_binary(endpoint, plaintext, "application/octet-stream");
    std::string token = body.at("token").get<std::string>();
    std::cout << token << "\n";
}

} // namespace amanda
