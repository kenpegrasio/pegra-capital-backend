#include "user.h"

void setup_user_routes(crow::SimpleApp& app, mongocxx::database& db) {
    // Register
    CROW_ROUTE(app, "/user/register").methods("POST"_method)([&db](const crow::request& req) {
        mongocxx::collection users = db["users"];
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        if (!body.has("email") || !body.has("password"))
            return crow::response(400, "Missing email or password");

        std::string email = body["email"].s();
        std::string password = body["password"].s();

        std::cout << "email password " << email << " " << password << std::endl;
        
        char salt[BCRYPT_HASHSIZE];
        bcrypt_gensalt(12, salt);

        char hash[BCRYPT_HASHSIZE];
        bcrypt_hashpw(password.c_str(), salt, hash);

        std::string hashed_password(hash);

        std::cout << "Hashed password " << hashed_password << std::endl;

        // Check if user already exists
        auto existing = users.find_one(make_document(kvp("email", email)));
        if (existing) {
            return crow::response(409, "User already exists.");
        }

        std::cout << "No existing user is found" << std::endl;

        // Insert new user
        users.insert_one(make_document(
            kvp("email", email),
            kvp("password", hashed_password)
        ));

        return crow::response(201, "User registered successfully.");
    });

    // Login
    CROW_ROUTE(app, "/user/login").methods("POST"_method)([&db](const crow::request& req) {
        const char* jwt_secret = std::getenv("JWT_SECRET");
        if (!jwt_secret) {
            std::cerr << "JWT_SECRET is not initialized" << std::endl;
            exit(1);
        }
        mongocxx::collection users = db["users"];
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        std::string email = body["email"].s();
        std::string password = body["password"].s();

        auto user = users.find_one(make_document(
            kvp("email", email)
        ));

        if (!user) {
            return crow::response(401, "Invalid email or password.");
        }

        auto element = user->view()["password"];
        std::string stored_hash{element.get_string().value};

        int valid = bcrypt_checkpw(password.c_str(), stored_hash.c_str());

        if (valid != 0) {
            return crow::response(401, "Invalid email or password.");
        }

        std::string json_str = bsoncxx::to_json(user->view());
        // std::cout << "User found: " << json_str << std::endl;

        auto token = jwt::create()
            .set_issuer("pegra")
            .set_subject(email)
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes{60})
            .sign(jwt::algorithm::hs256(jwt_secret));

        crow::json::wvalue res;
        res["token"] = token;
        return crow::response{res};
    });


    CROW_ROUTE(app, "/user/me").methods("GET"_method)([](const crow::request& req) {
        const char* jwt_secret = std::getenv("JWT_SECRET");
        if (!jwt_secret) {
            std::cerr << "JWT_SECRET is not initialized" << std::endl;
            exit(1);
        }
        auto auth_header = req.get_header_value("Authorization");

        if (auth_header.substr(0, 7) != "Bearer ") {
            return crow::response(401, "Missing or invalid token");
        }

        std::string token = auth_header.substr(7);

        try {
            auto decoded = jwt::decode(token);
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{jwt_secret})
                .with_issuer("pegra");

            verifier.verify(decoded);

            std::string email = decoded.get_subject();

            crow::json::wvalue res;
            res["email"] = email;
            res["message"] = "Authenticated request";
            return crow::response{res};

        } catch (const std::exception& e) {
            return crow::response(401, std::string("Invalid token: ") + e.what());
        }
    });
}