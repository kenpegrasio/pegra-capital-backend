// routes/auth_routes.cpp
#include "auth_routes.h"
#include "../controllers/auth_controller.h"

void register_auth_routes(crow::App<crow::CORSHandler>& app, mongocxx::database& db) {
    CROW_ROUTE(app, "/user/register").methods("POST"_method)([&db](const crow::request& req, crow::response& res) {
        handle_register(req, res, db);
    });

    CROW_ROUTE(app, "/user/login").methods("POST"_method)([&db](const crow::request& req, crow::response& res) {
        handle_login(req, res, db);
    });

    CROW_ROUTE(app, "/user/me").methods("GET"_method)([&db](const crow::request& req) {
        return handle_me(req, db);
    });
}