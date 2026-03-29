// amanda/cmd/edit.cpp
#include "cmd/commands.hpp"
#include "client/client.hpp"
#include "util/editor_util.h"
#include <iostream>
#include <string>
#include <vector>

namespace amanda {

/// Map a MIME type to a file extension for editor syntax highlighting.
static std::string ext_for_mimetype(const std::string& ct) {
    if (ct.find("text/markdown")    != std::string::npos) return ".md";
    if (ct.find("application/json") != std::string::npos) return ".json";
    if (ct.find("text/yaml")        != std::string::npos) return ".yaml";
    if (ct.find("application/yaml") != std::string::npos) return ".yaml";
    if (ct.find("text/html")        != std::string::npos) return ".html";
    if (ct.find("text/")            != std::string::npos) return ".txt";
    return "";  // binary — no extension hint
}

void cmd_edit(HttpClient& client, AmandaConfig& /*cfg*/, const Args& args) {
    if (args.empty() || args[0].empty()) {
        std::cerr << "Usage: amanda edit <path>\n";
        return;
    }
    const std::string path = args[0];

    // 1. Fetch current plaintext (server decrypts; LRU cache hit avoids re-decrypt)
    std::string content_type;
    std::vector<uint8_t> original;
    try {
        original = client.get_binary("/secrets" + path, content_type);
    } catch (const std::exception& e) {
        std::cerr << "Edit failed: " << e.what() << "\n";
        return;
    }

    // 2. Open in editor
    const std::string ext = ext_for_mimetype(content_type);
    std::string edited;
    try {
        edited = open_in_editor(std::string(original.begin(), original.end()), ext);
    } catch (const EditorError& e) {
        std::cerr << "Edit failed: " << e.what() << "\n";
        return;
    }

    // 3. Skip PUT if nothing changed
    std::vector<uint8_t> new_data(edited.begin(), edited.end());
    if (new_data == original) {
        std::cout << "No changes made.\n";
        return;
    }

    // 4. Write updated content back
    try {
        client.put_binary("/secrets" + path, new_data, content_type);
        std::cout << "Edited successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "Edit failed: " << e.what() << "\n";
    }
}

} // namespace amanda
