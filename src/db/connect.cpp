#include "connect.h"

mongocxx::database init_db() {
    const char* uri_str = std::getenv("MONGODB_URI");
    if (!uri_str) {
        std::cerr << "ERROR: MONGODB_URI is not set!" << std::endl;
        exit(1);
    }
    static mongocxx::client client{mongocxx::uri{uri_str}};
    return client["pegra"];
}