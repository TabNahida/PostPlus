#include <postplus/core.hpp>
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

using namespace postplus;
namespace {
std::string read_password() {
    struct TerminalEcho {
#ifdef _WIN32
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        DWORD original = 0;
        bool changed = GetConsoleMode(input, &original) && SetConsoleMode(input, original & ~ENABLE_ECHO_INPUT);
        ~TerminalEcho() { if (changed) SetConsoleMode(input, original); }
#else
        termios original{};
        bool changed = false;
        TerminalEcho() {
            if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &original) == 0) {
                auto hidden = original; hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
                changed = tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0;
            }
        }
        ~TerminalEcho() { if (changed) tcsetattr(STDIN_FILENO, TCSAFLUSH, &original); }
#endif
    } terminal;
    std::cerr << "Password: ";
    std::string password;
    if (!std::getline(std::cin,password)) throw std::runtime_error("password input failed");
    std::cerr << '\n';
    return password;
}
}
int main(int argc, char** argv) {
    if (argc < 2 || std::string_view(argv[1]) == "--help") {
        std::cout << "PostPlus administration (internal RPC)\n"
                     "  postplus-ctl create-user EMAIL [--admin] [--config PATH]\n"
                     "  postplus-ctl password EMAIL [--config PATH]\n"
                     "  postplus-ctl users|stats|queue [--config PATH]\n"
                     "Passwords are read from stdin, never from command arguments.\n";
        return 0;
    }
    return service_main("ctl",argc,argv,[&](const Config& config) {
        const std::string command = argv[1];
        Json result;
        if (command == "create-user" || command == "password") {
            if (argc < 3 || !valid_address(argv[2])) throw std::invalid_argument("a full email address is required");
            bool admin = false;
            for (int i=3; i<argc; ++i) if (std::string_view(argv[i]) == "--admin") admin = true;
            const auto password = read_password();
            result = rpc(config,"auth",{{"op",command == "password" ? "change_password" : "create"},{"username",lower(argv[2])},{"password",password},{"admin",admin}});
        } else if (command == "users") result = rpc(config,"auth",{{"op","list"}});
        else if (command == "stats") result = rpc(config,"storage",{{"op","stats"}});
        else if (command == "queue") {
            result = rpc(config,"storage",{{"op","queue_inspect"},{"limit",100}});
        } else throw std::invalid_argument("unknown command; use --help");
        if (!result.value("ok",false)) throw std::runtime_error(result.value("error","operation failed"));
        std::cout << result.dump(2) << '\n';
    });
}
