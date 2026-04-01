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
    std::string out = capture([&]{ e.emit_trays({}); });
    check("token present: TOKEN=abc123==", contains(out, "TOKEN=abc123=="));
}

static void test_token_line_no_token() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, true, "");
    std::string out = capture([&]{ e.emit_trays({}); });
    check("no token: placeholder in output", contains(out, "<your-bearer-token>"));
}

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    test_tls_flags_insecure();
    test_tls_flags_cacert();
    test_tls_flags_none();
    test_token_line_with_token();
    test_token_line_no_token();

    std::cout << "\n" << (failures == 0 ? "All tests passed.\n"
                                        : std::to_string(failures) + " test(s) FAILED.\n");
    return failures == 0 ? 0 : 1;
}
