// amanda/util/editor_util.h
#pragma once
#include <stdexcept>
#include <string>

/// Thrown when the editor session fails unrecoverably.
class EditorError : public std::runtime_error {
public:
    explicit EditorError(const std::string& msg) : std::runtime_error(msg) {}
};

/// Opens the user's preferred editor ($VISUAL > $EDITOR > vi) with
/// initial_text pre-loaded. Blocks until the editor exits, then returns
/// the full file contents. file_extension (e.g. ".md") enables syntax
/// highlighting; include the leading dot.
/// @throws EditorError on temp-file, editor, or read-back failure.
std::string open_in_editor(const std::string& initial_text,
                            const std::string& file_extension = "");
