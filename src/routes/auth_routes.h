#include <crow.h>
#include <mongocxx/database.hpp>
#include "crow/middlewares/cors.h"

void register_auth_routes(crow::App<crow::CORSHandler>& app, mongocxx::database& db);