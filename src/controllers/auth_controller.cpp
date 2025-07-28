#include "auth_controller.h"

void handle_register(const crow::request& req, crow::response& res,
                     mongocxx::database& db) {
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

  std::string hashed_password = hash(password);

  auto email_existing = users.find_one(make_document(kvp("email", email)));
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

  users.insert_one(make_document(kvp("username", username), kvp("email", email),
                                 kvp("password", hashed_password),
                                 kvp("name", name)));

  res.code = 201;
  res.body = "User registered successfully.";
  res.end();
  return;
}

void handle_login(const crow::request& req, crow::response& res,
                  mongocxx::database& db) {
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
  if (!check_password(password, stored_hash)) {
    res.code = 401;
    res.body = "Incorrect Password";
    res.end();
    return;
  }

  auto token = create_token(emailOrUsername);

  crow::json::wvalue json_res;
  json_res["token"] = token;

  res = crow::response{json_res};
  res.end();
  return;
}

crow::response handle_me(const crow::request& req, mongocxx::database& db) {
  const char* jwt_secret = getenv("JWT_SECRET");

  crow::response res;

  auto auth_header = req.get_header_value("Authorization");
  if (auth_header.substr(0, 7) != "Bearer ") {
    res.code = 401;
    res.body = "Missing or invalid token";
    return res;
  }

  std::string token = auth_header.substr(7);

  try {
    auto decoded = verify_token(token);

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
    json_res["username"] = view["username"].get_string().value.to_string();
    json_res["name"] = view["name"].get_string().value.to_string();

    res = crow::response{json_res};
    return res;

  } catch (const std::exception& e) {
    res.code = 401;
    res.body = std::string("Invalid token: ") + e.what();
    return res;
  }
}