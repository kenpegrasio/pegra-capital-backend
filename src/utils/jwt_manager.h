#include <string>
#include <jwt-cpp/jwt.h>

#include "env_manager.h"

std::string create_token(const std::string& subject);
jwt::decoded_jwt<jwt::traits::kazuho_picojson> verify_token(const std::string& token);