#include <crow.h>
#include <mongocxx/database.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/types.hpp>
#include <jwt-cpp/jwt.h>

#include "../bcrypt/bcrypt.h"

using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_document;

void setup_user_routes(crow::SimpleApp& app, mongocxx::database& db);