#include "cmd/curl_emitter.hpp"
#include <fmt/format.h>
#include <iostream>
#include <stdexcept>

namespace amanda {

CurlEmitter::CurlEmitter(const AmandaConfig& cfg, bool insecure,
                         const std::string& token_b64)
    : cfg_(cfg), insecure_(insecure), token_b64_(token_b64)
{
    server_url_ = cfg_.server_url;
    // Strip trailing slash if present
    if (!server_url_.empty() && server_url_.back() == '/')
        server_url_.pop_back();
}

std::string CurlEmitter::tls_flags() const {
    if (insecure_) return "-k";
    if (!cfg_.cacert.empty()) return "--cacert " + cfg_.cacert;
    return "";
}

std::string CurlEmitter::token_line() const {
    if (!token_b64_.empty())
        return fmt::format("TOKEN={}\n", token_b64_);
    return "TOKEN=<your-bearer-token>\n";
}

std::string CurlEmitter::host_line() const {
    return fmt::format("HOST={}\n", server_url_);
}

std::string CurlEmitter::auth_preamble() const {
    return host_line() + token_line();
}

void CurlEmitter::emit_login(const Args& args) {
    std::unordered_map<std::string, std::string> d;
    d["host"]     = server_url_;
    d["tls"]      = tls_flags();
    d["username"] = cfg_.username.empty() ? "<username>" : cfg_.username;
    d["password"] = "<password>";   // interactive; placeholder by design

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--username" && i + 1 < args.size())
            d["username"] = args[++i];
    }

    std::string tls = d["tls"].empty() ? "" : " " + d["tls"];
    std::cout << fmt::format(
        "TOKEN=$(curl -s{tls} -X POST \"{host}/login\" \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -d '{{\"username\":\"{username}\",\"password\":\"{password}\"}}' \\\n"
        "  | jq -r .token)\n"
        "\n"
        "echo \"Token: $TOKEN\"\n",
        fmt::arg("tls",      tls),
        fmt::arg("host",     d["host"]),
        fmt::arg("username", d["username"]),
        fmt::arg("password", d["password"])
    ) << "\n";
}

void CurlEmitter::emit_logout(const Args& /*args*/) {
    std::unordered_map<std::string, std::string> d;
    d["host"] = server_url_;
    d["tls"]  = tls_flags();

    std::string tls = d["tls"].empty() ? "" : " " + d["tls"];
    std::cout << auth_preamble()
              << fmt::format(
        "curl -s{tls} -X DELETE \"{host}/logout\" \\\n"
        "  -H \"Authorization: Bearer $TOKEN\"\n",
        fmt::arg("tls",  tls),
        fmt::arg("host", d["host"])
    ) << "\n";
}

void CurlEmitter::emit_put(const Args& args) {
    std::unordered_map<std::string, std::string> d;
    d["path"]      = "";
    d["from_file"] = "";
    d["from_text"] = "";
    d["mimetype"]  = "";
    d["tray"]      = cfg_.default_tray.empty() ? "system" : cfg_.default_tray;

    bool path_set = false;
    for (size_t i = 0; i < args.size(); ++i) {
        if      (args[i] == "--from-file" && i + 1 < args.size()) d["from_file"] = args[++i];
        else if (args[i] == "--from-text" && i + 1 < args.size()) d["from_text"] = args[++i];
        else if (args[i] == "--mimetype"  && i + 1 < args.size()) d["mimetype"]  = args[++i];
        else if (args[i] == "--tray"      && i + 1 < args.size()) d["tray"]      = args[++i];
        else if (!path_set && !args[i].empty() && args[i][0] != '-') {
            d["path"] = args[i]; path_set = true;
        }
    }

    if (d["path"].empty())
        throw std::invalid_argument("put --curl: vault path is required");

    if (d["mimetype"].empty()) {
        if (!d["from_file"].empty()) {
            d["mimetype"] = "application/octet-stream";
        } else if (!d["from_text"].empty()) {
            d["mimetype"] = "text/plain";
        } else {
            d["mimetype"] = "application/octet-stream";
        }
    }

    std::string tls = tls_flags().empty() ? "" : " " + tls_flags();

    std::string data_arg;
    if (!d["from_text"].empty()) {
        data_arg = fmt::format("  --data-raw \"{}\"", d["from_text"]);
    } else if (!d["from_file"].empty()) {
        data_arg = fmt::format("  --data-binary \"@{}\"", d["from_file"]);
    } else {
        data_arg = "  --data-binary @-";
    }

    std::cout << auth_preamble()
              << fmt::format(
        "curl -s{tls} -X POST \"$HOST/secrets{path}?tray={tray}\" \\\n"
        "  -H \"Authorization: Bearer $TOKEN\" \\\n"
        "  -H \"Content-Type: {mime}\" \\\n"
        "{data}\n",
        fmt::arg("tls",  tls),
        fmt::arg("path", d["path"]),
        fmt::arg("tray", d["tray"]),
        fmt::arg("mime", d["mimetype"]),
        fmt::arg("data", data_arg)
    ) << "\n";
}

void CurlEmitter::emit_get(const Args& args) {
    std::unordered_map<std::string, std::string> d;
    d["path"]    = "";
    d["to_file"] = "";

    bool path_set = false;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--to-file" && i + 1 < args.size()) d["to_file"] = args[++i];
        else if (!path_set && !args[i].empty() && args[i][0] != '-') {
            d["path"] = args[i]; path_set = true;
        }
    }

    if (d["path"].empty())
        throw std::invalid_argument("get --curl: vault path is required");

    std::string tls = tls_flags().empty() ? "" : " " + tls_flags();
    std::string output_redir = d["to_file"].empty() ? "" :
        fmt::format(" \\\n  --output \"{}\"", d["to_file"]);

    std::cout << auth_preamble()
              << fmt::format(
        "curl -s{tls} -X GET \"$HOST/secrets{path}\" \\\n"
        "  -H \"Authorization: Bearer $TOKEN\"{output}\n",
        fmt::arg("tls",    tls),
        fmt::arg("path",   d["path"]),
        fmt::arg("output", output_redir)
    ) << "\n";
}

void CurlEmitter::emit_meta(const Args& args) {
    std::unordered_map<std::string, std::string> d;
    d["path"] = "";

    for (const auto& a : args)
        if (!a.empty() && a[0] != '-' && d["path"].empty()) d["path"] = a;

    if (d["path"].empty())
        throw std::invalid_argument("meta --curl: vault path is required");

    std::string tls = tls_flags().empty() ? "" : " " + tls_flags();
    std::cout << auth_preamble()
              << fmt::format(
        "curl -s{tls} -X GET \"$HOST/secrets{path}/meta\" \\\n"
        "  -H \"Authorization: Bearer $TOKEN\"\n",
        fmt::arg("tls",  tls),
        fmt::arg("path", d["path"])
    ) << "\n";
}

void CurlEmitter::emit_list(const Args& args) {
    std::unordered_map<std::string, std::string> d;
    d["prefix"] = "";

    for (size_t i = 0; i < args.size(); ++i)
        if (args[i] == "--prefix" && i + 1 < args.size()) d["prefix"] = args[++i];

    std::string endpoint = "$HOST/secrets";
    if (!d["prefix"].empty()) endpoint += "?prefix=" + d["prefix"];

    std::string tls = tls_flags().empty() ? "" : " " + tls_flags();
    std::cout << auth_preamble()
              << fmt::format(
        "curl -s{tls} -X GET \"{endpoint}\" \\\n"
        "  -H \"Authorization: Bearer $TOKEN\"\n",
        fmt::arg("tls",      tls),
        fmt::arg("endpoint", endpoint)
    ) << "\n";
}

void CurlEmitter::emit_link(const Args& args) {
    if (args.size() < 2)
        throw std::invalid_argument("link --curl: usage: link <target-path> <v-path>");

    std::unordered_map<std::string, std::string> d;
    d["target"] = args[0];
    d["link"]   = args[1];

    std::string tls = tls_flags().empty() ? "" : " " + tls_flags();
    std::cout << auth_preamble()
              << fmt::format(
        "curl -s{tls} -X POST \"$HOST/links\" \\\n"
        "  -H \"Authorization: Bearer $TOKEN\" \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -d '{{\"target\":\"{target}\",\"link\":\"{link}\"}}'\n",
        fmt::arg("tls",    tls),
        fmt::arg("target", d["target"]),
        fmt::arg("link",   d["link"])
    ) << "\n";
}

void CurlEmitter::emit_health(const Args& /*args*/) {
    std::unordered_map<std::string, std::string> d;
    d["host"] = server_url_;
    d["tls"]  = tls_flags();

    std::string tls = d["tls"].empty() ? "" : " " + d["tls"];
    std::cout << fmt::format(
        "curl -s{tls} -X GET \"{host}/health\"\n",
        fmt::arg("tls",  tls),
        fmt::arg("host", d["host"])
    ) << "\n";
}
void CurlEmitter::emit_keygen(const Args& args) {
    std::unordered_map<std::string, std::string> d;
    d["alias"]   = "<alias>";
    d["profile"] = "";

    for (size_t i = 0; i < args.size(); ++i) {
        if      (args[i] == "--alias"   && i + 1 < args.size()) d["alias"]   = args[++i];
        else if (args[i] == "--profile" && i + 1 < args.size()) d["profile"] = args[++i];
    }

    std::string body_inner = fmt::format("\"alias\":\"{}\"", d["alias"]);
    if (!d["profile"].empty())
        body_inner += fmt::format(",\"profile\":\"{}\"", d["profile"]);

    std::string tls = tls_flags().empty() ? "" : " " + tls_flags();
    std::cout << auth_preamble()
              << fmt::format(
        "curl -s{tls} -X POST \"$HOST/trays\" \\\n"
        "  -H \"Authorization: Bearer $TOKEN\" \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -d '{{{body}}}'\n",
        fmt::arg("tls",  tls),
        fmt::arg("body", body_inner)
    ) << "\n";
}

void CurlEmitter::emit_trays(const Args& /*args*/) {
    std::string tls = tls_flags().empty() ? "" : " " + tls_flags();
    std::cout << auth_preamble()
              << fmt::format(
        "curl -s{tls} -X GET \"$HOST/trays\" \\\n"
        "  -H \"Authorization: Bearer $TOKEN\"\n",
        fmt::arg("tls", tls)
    ) << "\n";
}
void CurlEmitter::emit_wrap       (const Args&) { throw std::runtime_error("emit_wrap: not yet implemented"); }
void CurlEmitter::emit_newuser    (const Args&) { throw std::runtime_error("emit_newuser: not yet implemented"); }
void CurlEmitter::emit_listuser   (const Args&) { throw std::runtime_error("emit_listuser: not yet implemented"); }
void CurlEmitter::emit_changepass (const Args&) { throw std::runtime_error("emit_changepass: not yet implemented"); }

} // namespace amanda
