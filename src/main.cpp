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

#include "db/connect.h"
#include "routes/user.h"

int main() {
    std::cout << "Starting Pegra backend" << std::endl;
    static mongocxx::instance inst{};
    mongocxx::database db = init_db();
    crow::SimpleApp app;     

    CROW_ROUTE(app, "/")([] {
        return crow::response(200, "Welcome to Pegra Backend");
    });

    setup_user_routes(app, db);

    std::cout << "Server is running on http://localhost:18080/" << std::endl;
    app.port(18080).multithreaded().run();
}
