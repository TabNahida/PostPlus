#pragma once
#include <string>
#include <string_view>

namespace postplus {
// UTF-8 logical mailbox names, at most 255 bytes and 16 slash-separated
// components. System mailbox names retain their established spelling.
std::string normalize_mail_folder(std::string_view input);
bool is_system_mail_folder(std::string_view name);
}
