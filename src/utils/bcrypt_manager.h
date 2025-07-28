#include "bcrypt.h"
#include <string>

std::string hash(std::string password);
bool check_password(std::string candidate, std::string stored);