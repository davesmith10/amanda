#include "cmd/curl_emitter.hpp"
#include <functional>
#include <iostream>
#include <sstream>
#include <string>

// Redirects std::cout to a string for the duration of fn()
static std::string capture(std::function<void()> fn) {
    std::ostringstream oss;
    std::streambuf* old = std::cout.rdbuf(oss.rdbuf());
    try { fn(); } catch (...) {}
    std::cout.rdbuf(old);
    return oss.str();
}

static int failures = 0;

static void check(const std::string& label, bool ok) {
    std::cout << (ok ? "PASS" : "FAIL") << ": " << label << "\n";
    if (!ok) ++failures;
}

static bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// ── helper behavior tests (via emit_health / emit_trays) ──────────────────────

static void test_tls_flags_insecure() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, /*insecure=*/true, "");
    std::string out = capture([&]{ e.emit_health({}); });
    check("insecure: curl uses -k", contains(out, "-k"));
}

static void test_tls_flags_cacert() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    cfg.cacert = "/etc/ssl/myca.pem";
    amanda::CurlEmitter e(cfg, /*insecure=*/false, "");
    std::string out = capture([&]{ e.emit_health({}); });
    check("cacert: curl uses --cacert", contains(out, "--cacert /etc/ssl/myca.pem"));
}

static void test_tls_flags_none() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://myserver.example.com:8443";
    amanda::CurlEmitter e(cfg, false, "");
    std::string out = capture([&]{ e.emit_health({}); });
    check("no tls flag: no -k in output", !contains(out, " -k"));
    check("no tls flag: no --cacert in output", !contains(out, "--cacert"));
}

static void test_token_line_with_token() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, true, "abc123==");
    std::string out = capture([&]{ e.emit_logout({}); });
    check("token present: TOKEN=abc123==", contains(out, "TOKEN=abc123=="));
}

static void test_token_line_no_token() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, true, "");
    std::string out = capture([&]{ e.emit_logout({}); });
    check("no token: placeholder in output", contains(out, "<your-bearer-token>"));
}

static void test_emit_login_default() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    cfg.username   = "alice";
    amanda::CurlEmitter e(cfg, true, "");
    std::string out = capture([&]{ e.emit_login({}); });
    check("login: TOKEN=$(curl",         contains(out, "TOKEN=$(curl"));
    check("login: POST /login",          contains(out, "POST"));
    check("login: username alice",       contains(out, "alice"));
    check("login: password placeholder", contains(out, "<password>"));
    check("login: jq -r .token",         contains(out, "jq -r .token"));
    check("login: -k insecure",          contains(out, "-k"));
}

static void test_emit_login_override_username() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "");
    std::string out = capture([&]{ e.emit_login({"--username", "bob"}); });
    check("login: --username override", contains(out, "bob"));
}

static void test_emit_logout() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "mytoken==");
    std::string out = capture([&]{ e.emit_logout({}); });
    check("logout: DELETE /logout",       contains(out, "DELETE"));
    check("logout: Authorization header", contains(out, "Authorization: Bearer $TOKEN"));
    check("logout: TOKEN=mytoken==",      contains(out, "TOKEN=mytoken=="));
}

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    test_tls_flags_insecure();
    test_tls_flags_cacert();
    test_tls_flags_none();
    test_token_line_with_token();
    test_token_line_no_token();
    test_emit_login_default();
    test_emit_login_override_username();
    test_emit_logout();

    std::cout << "\n" << (failures == 0 ? "All tests passed.\n"
                                        : std::to_string(failures) + " test(s) FAILED.\n");
    return failures == 0 ? 0 : 1;
}
