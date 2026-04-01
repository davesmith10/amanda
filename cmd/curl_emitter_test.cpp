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

// ── put / get / meta / list ───────────────────────────────────────────────────

static void test_emit_put_from_text() {
    amanda::AmandaConfig cfg;
    cfg.server_url   = "https://localhost:8443";
    cfg.default_tray = "team-a";
    amanda::CurlEmitter e(cfg, true, "tok==");
    std::string out = capture([&]{
        e.emit_put({"/team-a/dbpassword", "--from-text", "hunter2"});
    });
    check("put/text: POST /secrets",  contains(out, "POST"));
    check("put/text: path in URL",    contains(out, "/team-a/dbpassword"));
    check("put/text: tray=team-a",    contains(out, "tray=team-a"));
    check("put/text: --data-raw",     contains(out, "--data-raw"));
    check("put/text: hunter2",        contains(out, "hunter2"));
    check("put/text: TOKEN=tok==",    contains(out, "TOKEN=tok=="));
}

static void test_emit_put_from_file() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{
        e.emit_put({"/mypath", "--from-file", "/tmp/cert.pem"});
    });
    check("put/file: --data-binary @file", contains(out, "--data-binary \"@/tmp/cert.pem\""));
}

static void test_emit_put_stdin() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{
        e.emit_put({"/mypath"});
    });
    check("put/stdin: --data-binary @-", contains(out, "--data-binary @-"));
}

static void test_emit_get() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, true, "tok==");
    std::string out = capture([&]{ e.emit_get({"/foo/bar"}); });
    check("get: GET /secrets",   contains(out, "GET"));
    check("get: path in URL",    contains(out, "/foo/bar"));
    check("get: auth header",    contains(out, "Authorization: Bearer $TOKEN"));
}

static void test_emit_get_to_file() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_get({"/foo/bar", "--to-file", "/tmp/out.txt"}); });
    check("get/tofile: --output flag", contains(out, "--output \"/tmp/out.txt\""));
}

static void test_emit_meta() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_meta({"/foo/bar"}); });
    check("meta: /meta suffix", contains(out, "/foo/bar/meta"));
}

static void test_emit_list_no_prefix() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_list({}); });
    check("list: GET /secrets", contains(out, "/secrets"));
}

static void test_emit_list_with_prefix() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_list({"--prefix", "/team-a"}); });
    check("list: prefix param", contains(out, "prefix=/team-a"));
}

// ── link / keygen / trays ─────────────────────────────────────────────────────

static void test_emit_link() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_link({"/real/path", "/link/path"}); });
    check("link: POST /links",       contains(out, "POST"));
    check("link: target in body",    contains(out, "/real/path"));
    check("link: link in body",      contains(out, "/link/path"));
    check("link: Content-Type json", contains(out, "application/json"));
}

static void test_emit_keygen_with_alias() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_keygen({"--alias", "my-tray"}); });
    check("keygen: POST /trays",   contains(out, "POST"));
    check("keygen: alias in body", contains(out, "my-tray"));
}

static void test_emit_trays() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_trays({}); });
    check("trays: GET /trays",    contains(out, "GET"));
    check("trays: /trays in URL", contains(out, "/trays"));
}

// ── wrap / newuser / listuser / changepass ────────────────────────────────────

static void test_emit_wrap() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_wrap({"--ttl", "7200"}); });
    check("wrap: POST /wrap",        contains(out, "POST"));
    check("wrap: ttl=7200",          contains(out, "ttl=7200"));
    check("wrap: --data-binary @-",  contains(out, "--data-binary @-"));
    check("wrap: jq .token",         contains(out, "jq -r .token"));
}

static void test_emit_newuser() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_newuser({"--username", "bob"}); });
    check("newuser: POST /users/invite", contains(out, "/users/invite"));
    check("newuser: username bob",       contains(out, "bob"));
}

static void test_emit_listuser() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_listuser({}); });
    check("listuser: GET /users",  contains(out, "GET"));
    check("listuser: /users URL",  contains(out, "/users"));
}

static void test_emit_changepass() {
    amanda::AmandaConfig cfg;
    cfg.server_url = "https://localhost:8443";
    cfg.username   = "alice";
    amanda::CurlEmitter e(cfg, false, "tok==");
    std::string out = capture([&]{ e.emit_changepass({}); });
    check("changepass: POST .../password", contains(out, "/users/alice/password"));
    check("changepass: password placeholder", contains(out, "<new-password>"));
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
    test_emit_put_from_text();
    test_emit_put_from_file();
    test_emit_put_stdin();
    test_emit_get();
    test_emit_get_to_file();
    test_emit_meta();
    test_emit_list_no_prefix();
    test_emit_list_with_prefix();
    test_emit_link();
    test_emit_keygen_with_alias();
    test_emit_trays();
    test_emit_wrap();
    test_emit_newuser();
    test_emit_listuser();
    test_emit_changepass();

    std::cout << "\n" << (failures == 0 ? "All tests passed.\n"
                                        : std::to_string(failures) + " test(s) FAILED.\n");
    return failures == 0 ? 0 : 1;
}
