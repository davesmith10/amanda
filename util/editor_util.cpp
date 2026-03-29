// amanda/util/editor_util.cpp
#define _GNU_SOURCE
#include "editor_util.h"
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

std::string open_in_editor(const std::string& initial_text,
                            const std::string& file_extension) {
    std::string tmpl;
    int fd = -1;

    if (file_extension.empty()) {
        char buf[] = "/tmp/sarek_XXXXXX";
        fd = mkstemp(buf);
        if (fd == -1) throw EditorError(std::string("mkstemp failed: ") + strerror(errno));
        tmpl = buf;
    } else {
        std::string s = "/tmp/sarek_XXXXXX" + file_extension;
        std::vector<char> buf(s.begin(), s.end());
        buf.push_back('\0');
        fd = mkstemps(buf.data(), static_cast<int>(file_extension.size()));
        if (fd == -1) throw EditorError(std::string("mkstemps failed: ") + strerror(errno));
        tmpl = std::string(buf.data());
    }

    // RAII: always unlink temp file and close fd on any exit path
    struct Guard {
        std::string path;
        int fd;
        ~Guard() {
            if (fd != -1) ::close(fd);
            ::unlink(path.c_str());
        }
    } guard{tmpl, fd};

    if (!initial_text.empty()) {
        ssize_t n = write(fd, initial_text.data(), initial_text.size());
        if (n < 0 || static_cast<size_t>(n) != initial_text.size()) {
            throw EditorError(std::string("write to temp file failed: ") + strerror(errno));
        }
    }
    ::close(fd);
    guard.fd = -1;  // fd is now closed; Guard won't try to close it again

    const char* editor = std::getenv("VISUAL");
    if (!editor || editor[0] == '\0') editor = std::getenv("EDITOR");
    if (!editor || editor[0] == '\0') editor = "vi";

    std::string cmd = std::string(editor) + " " + tmpl;
    guard.fd = -1;  // fd already closed before calling system()
    int ret = std::system(cmd.c_str());
    if (ret == -1 || !WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
        int code = (ret != -1 && WIFEXITED(ret)) ? WEXITSTATUS(ret) : ret;
        throw EditorError(std::string("editor '") + editor +
                          "' exited with status " + std::to_string(code));
    }

    std::ifstream ifs(tmpl);
    if (!ifs.is_open())
        throw EditorError("failed to read temp file after editing");

    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}
