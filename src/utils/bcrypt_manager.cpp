#include "bcrypt_manager.h"

std::string hash(std::string password) {
  char salt[BCRYPT_HASHSIZE];
  bcrypt_gensalt(12, salt);
  char hash[BCRYPT_HASHSIZE];
  bcrypt_hashpw(password.c_str(), salt, hash);
  return hash;
}

bool check_password(std::string candidate, std::string stored) {
    return bcrypt_checkpw(candidate.c_str(), stored.c_str()) == 0;
}