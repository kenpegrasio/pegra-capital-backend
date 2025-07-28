#include "env_manager.h"

inline const char* get_env(const char* var) {
    const char* val = std::getenv(var);
    if (!val) throw std::runtime_error(std::string("Missing env var: ") + var);
    return val;
}