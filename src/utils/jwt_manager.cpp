#include "jwt_manager.h"

std::string create_token(const std::string& subject) {
  const char* jwt_secret = getenv("JWT_SECRET");
  return jwt::create()
      .set_issuer("pegra")
      .set_subject(subject)
      .set_issued_at(std::chrono::system_clock::now())
      .set_expires_at(std::chrono::system_clock::now() +
                      std::chrono::minutes{60})
      .sign(jwt::algorithm::hs256(jwt_secret));
}

jwt::decoded_jwt<jwt::traits::kazuho_picojson> verify_token(const std::string& token) {
  const char* jwt_secret = getenv("JWT_SECRET");
  auto decoded = jwt::decode(token);
  auto verifier = jwt::verify()
                      .allow_algorithm(jwt::algorithm::hs256{jwt_secret})
                      .with_issuer("pegra");
  verifier.verify(decoded);
  return decoded;
}