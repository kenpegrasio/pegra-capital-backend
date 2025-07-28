#include <crow.h>

#include <cstdlib>
#include <iostream>
#include <mongocxx/client.hpp>
#include <mongocxx/collection.hpp>
#include <mongocxx/database.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>

#include "crow/middlewares/cors.h"
#include "db/connect.h"
#include "routes/auth_routes.h"

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

  register_auth_routes(app, db);

  std::cout << "Server is running on http://localhost:18080/" << std::endl;
  app.port(18080).multithreaded().run();
}
