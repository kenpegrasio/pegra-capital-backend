#include <crow.h>
#include <jwt-cpp/jwt.h>

#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/builder/basic/kvp.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/exception/exception.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/types.hpp>
#include <mongocxx/database.hpp>

#include "bcrypt.h"
#include "../utils/env_manager.h"

using bsoncxx::builder::basic::array;
using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_document;

void handle_register(const crow::request& req, crow::response& res,
                     mongocxx::database& db);
void handle_login(const crow::request& req, crow::response& res,
                  mongocxx::database& db);
crow::response handle_me(const crow::request& req, mongocxx::database& db);