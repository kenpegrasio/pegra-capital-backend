#include <iostream>
#include <cstdlib>
#include <crow.h>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/database.hpp>
#include <mongocxx/collection.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/builder/basic/kvp.hpp>
#include <bsoncxx/types.hpp>
#include <bsoncxx/exception/exception.hpp>

using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_document;

int main() {
    mongocxx::instance instance{};
    const std::string uri_str = std::getenv("MONGODB_URI");
    mongocxx::client client{mongocxx::uri{uri_str}};
    mongocxx::database db = client["pegra"];
    mongocxx::collection users = db["users"];

    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([] {
        return crow::response(200, "Welcome to Pegra Backend");
    });

    // Register
    CROW_ROUTE(app, "/user/register").methods("POST"_method)([&users](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        std::string email = body["email"].s();
        std::string password = body["password"].s();

        // Check if user already exists
        auto existing = users.find_one(make_document(kvp("email", email)));
        if (existing) {
            return crow::response(409, "User already exists.");
        }

        // Insert new user
        users.insert_one(make_document(
            kvp("email", email),
            kvp("password", password)
        ));

        return crow::response(201, "User registered successfully.");
    });

    // Login
    CROW_ROUTE(app, "/user/login").methods("POST"_method)([&users](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        std::string email = body["email"].s();
        std::string password = body["password"].s();

        auto found = users.find_one(make_document(
            kvp("email", email),
            kvp("password", password)
        ));

        if (found) {
            return crow::response(200, "Login successful.");
        } else {
            return crow::response(401, "Invalid email or password.");
        }
    });

    std::cout << "Server is running on http://localhost:18080/" << std::endl;
    app.port(18080).multithreaded().run();
}
