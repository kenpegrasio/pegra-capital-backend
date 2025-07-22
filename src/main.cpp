#include <crow.h>
#include <jwt-cpp/jwt.h>

#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/builder/basic/kvp.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/exception/exception.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/types.hpp>
#include <cstdlib>
#include <iostream>
#include <mongocxx/client.hpp>
#include <mongocxx/collection.hpp>
#include <mongocxx/database.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>

#include "bcrypt.h"
#include "crow/middlewares/cors.h"
#include "db/connect.h"

using bsoncxx::builder::basic::array;
using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_document;

int main() {
  std::cout << "Starting Pegra backend" << std::endl;
  static mongocxx::instance inst{};
  mongocxx::database db = init_db();

  crow::App<crow::CORSHandler> app;
  auto& cors = app.get_middleware<crow::CORSHandler>();

  cors.global()
      .origin("http://localhost:5173")  // frontend host
      .allow_credentials()
      .headers("Accept", "Origin", "Content-Type", "Authorization", "Refresh")
      .methods(crow::HTTPMethod::GET, crow::HTTPMethod::POST,
               crow::HTTPMethod::OPTIONS, crow::HTTPMethod::HEAD,
               crow::HTTPMethod::PUT, crow::HTTPMethod::DELETE);

  // Register
  CROW_ROUTE(app, "/user/register")
      .methods(
          "POST"_method)([&db](const crow::request& req, crow::response& res) {
        mongocxx::collection users = db["users"];
        auto body = crow::json::load(req.body);

        if (!body) {
          res.code = 400;
          res.body = "Invalid JSON";
          res.end();
          return;
        }
        if (!body.has("username")) {
          res.code = 400;
          res.body = "Missing username";
          res.end();
          return;
        }
        if (!body.has("email")) {
          res.code = 400;
          res.body = "Missing email";
          res.end();
          return;
        }
        if (!body.has("name")) {
          res.code = 400;
          res.body = "Missing name";
          res.end();
          return;
        }
        if (!body.has("password")) {
          res.code = 400;
          res.body = "Missing password";
          res.end();
          return;
        }

        std::string username = body["username"].s();
        std::string email = body["email"].s();
        std::string password = body["password"].s();
        std::string name = body["name"].s();

        char salt[BCRYPT_HASHSIZE];
        bcrypt_gensalt(12, salt);
        char hash[BCRYPT_HASHSIZE];
        bcrypt_hashpw(password.c_str(), salt, hash);
        std::string hashed_password(hash);

        auto email_existing =
            users.find_one(make_document(kvp("email", email)));
        if (email_existing) {
          res.code = 409;
          res.body = "Email already exists.";
          res.end();
          return;
        }

        auto username_existing =
            users.find_one(make_document(kvp("username", username)));
        if (username_existing) {
          res.code = 409;
          res.body = "Username already exists.";
          res.end();
          return;
        }

        users.insert_one(
            make_document(kvp("username", username), kvp("email", email),
                          kvp("password", hashed_password), kvp("name", name)));

        res.code = 201;
        res.body = "User registered successfully.";
        res.end();
        return;
      });

  // Login
  CROW_ROUTE(app, "/user/login")
      .methods("POST"_method)(
          [&db](const crow::request& req, crow::response& res) {
            const char* jwt_secret = std::getenv("JWT_SECRET");
            if (!jwt_secret) {
              std::cerr << "JWT_SECRET is not initialized" << std::endl;
              exit(1);
            }

            mongocxx::collection users = db["users"];
            auto body = crow::json::load(req.body);

            if (!body) {
              res.code = 400;
              res.body = "Invalid JSON";
              res.end();
              return;
            }
            if (!body.has("emailOrUsername")) {
              res.code = 400;
              res.body = "Missing Identifiers";
              res.end();
              return;
            }
            if (!body.has("password")) {
              res.code = 400;
              res.body = "Missing Password";
              res.end();
              return;
            }

            std::string emailOrUsername = body["emailOrUsername"].s();
            std::string password = body["password"].s();

            array or_array;
            or_array.append(make_document(kvp("email", emailOrUsername)));
            or_array.append(make_document(kvp("username", emailOrUsername)));

            auto user = users.find_one(make_document(kvp("$or", or_array)));

            if (!user) {
              res.code = 401;
              res.body = "User with such identifier is not found.";
              res.end();
              return;
            }

            auto element = user->view()["password"];
            std::string stored_hash = element.get_string().value.to_string();
            int valid = bcrypt_checkpw(password.c_str(), stored_hash.c_str());
            if (valid != 0) {
              res.code = 401;
              res.body = "Incorrect Password";
              res.end();
              return;
            }

            auto token = jwt::create()
                             .set_issuer("pegra")
                             .set_subject(emailOrUsername)
                             .set_issued_at(std::chrono::system_clock::now())
                             .set_expires_at(std::chrono::system_clock::now() +
                                             std::chrono::minutes{60})
                             .sign(jwt::algorithm::hs256(jwt_secret));

            crow::json::wvalue json_res;
            json_res["token"] = token;

            res = crow::response{json_res};
            res.end();
            return;
          });

  // Me
  CROW_ROUTE(app, "/user/me")
      .methods("GET"_method)([&db](const crow::request& req) {
        const char* jwt_secret = std::getenv("JWT_SECRET");
        if (!jwt_secret) {
          std::cerr << "JWT_SECRET is not initialized" << std::endl;
          exit(1);
        }

        crow::response res;

        auto auth_header = req.get_header_value("Authorization");
        if (auth_header.substr(0, 7) != "Bearer ") {
          res.code = 401;
          res.body = "Missing or invalid token";
          return res;
        }

        std::string token = auth_header.substr(7);

        try {
          auto decoded = jwt::decode(token);
          auto verifier =
              jwt::verify()
                  .allow_algorithm(jwt::algorithm::hs256{jwt_secret})
                  .with_issuer("pegra");

          verifier.verify(decoded);

          std::string emailOrUsername = decoded.get_subject();
          mongocxx::collection users = db["users"];

          array or_array;
          or_array.append(make_document(kvp("email", emailOrUsername)));
          or_array.append(make_document(kvp("username", emailOrUsername)));

          auto user = users.find_one(make_document(kvp("$or", or_array)));

          if (!user) {
            res.code = 404;
            res.body = "User with email decoded not found";
            return res;
          }

          auto view = user->view();
          crow::json::wvalue json_res;
          json_res["email"] = view["email"].get_string().value.to_string();
          json_res["username"] =
              view["username"].get_string().value.to_string();
          json_res["name"] = view["name"].get_string().value.to_string();

          res = crow::response{json_res};
          return res;

        } catch (const std::exception& e) {
          res.code = 401;
          res.body = std::string("Invalid token: ") + e.what();
          return res;
        }
      });

  std::cout << "Server is running on http://localhost:18080/" << std::endl;
  app.port(18080).multithreaded().run();
}
