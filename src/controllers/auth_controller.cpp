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

  users.insert_one(make_document(
      kvp("username", username), kvp("email", email),
      kvp("password", hashed_password), kvp("name", name),
      kvp("metamask_account", ""),
      kvp("wallet_provider",
          make_document(kvp("uuid", ""), kvp("name", ""), kvp("icon", "")))));

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

    auto wallet_provider_doc = view["wallet_provider"].get_document().value;
    crow::json::wvalue json_provider;
    json_provider["uuid"] =
        wallet_provider_doc["uuid"].get_string().value.to_string();
    json_provider["name"] =
        wallet_provider_doc["name"].get_string().value.to_string();
    json_provider["icon"] =
        wallet_provider_doc["icon"].get_string().value.to_string();

    json_res["email"] = view["email"].get_string().value.to_string();
    json_res["username"] = view["username"].get_string().value.to_string();
    json_res["name"] = view["name"].get_string().value.to_string();
    json_res["metamask_account"] =
        view["metamask_account"].get_string().value.to_string();
    json_res["wallet_provider"] = std::move(json_provider);

    res = crow::response{json_res};
    return res;

  } catch (const std::exception& e) {
    res.code = 401;
    res.body = std::string("Invalid token: ") + e.what();
    return res;
  }
}

void handle_update_metamask(const crow::request& req, crow::response& res,
                            mongocxx::database& db) {
  mongocxx::collection users = db["users"];
  auto body = crow::json::load(req.body);

  if (!body) {
    res.code = 400;
    res.body = "Invalid JSON";
    res.end();
    return;
  }

  if (!body.has("metamask_account")) {
    res.code = 400;
    res.body = "Missing Metamask Account Information";
    res.end();
    return;
  }

  if (!body.has("wallet_provider") || !body["wallet_provider"].has("uuid") ||
      !body["wallet_provider"].has("name") ||
      !body["wallet_provider"].has("icon")) {
    res.code = 400;
    res.body = "Missing or incomplete wallet_provider information";
    res.end();
    return;
  }

  auto auth_header = req.get_header_value("Authorization");
  if (auth_header.substr(0, 7) != "Bearer ") {
    res.code = 401;
    res.body = "Missing or invalid token";
    res.end();
    return;
  }

  std::string token = auth_header.substr(7);

  try {
    auto decoded = verify_token(token);
    std::string emailOrUsername = decoded.get_subject();

    bsoncxx::builder::basic::array or_array;
    or_array.append(bsoncxx::builder::basic::make_document(
        bsoncxx::builder::basic::kvp("email", emailOrUsername)));
    or_array.append(bsoncxx::builder::basic::make_document(
        bsoncxx::builder::basic::kvp("username", emailOrUsername)));

    auto user_filter = bsoncxx::builder::basic::make_document(
        bsoncxx::builder::basic::kvp("$or", or_array));

    auto user = users.find_one(user_filter.view());

    if (!user) {
      res.code = 404;
      res.body = "User not found";
      res.end();
      return;
    }

    // Perform the update
    auto update =
        bsoncxx::builder::basic::make_document(bsoncxx::builder::basic::kvp(
            "$set",
            bsoncxx::builder::basic::make_document(
                bsoncxx::builder::basic::kvp("metamask_account",
                                             body["metamask_account"].s()),
                bsoncxx::builder::basic::kvp(
                    "wallet_provider",
                    bsoncxx::builder::basic::make_document(
                        bsoncxx::builder::basic::kvp(
                            "uuid", body["wallet_provider"]["uuid"].s()),
                        bsoncxx::builder::basic::kvp(
                            "name", body["wallet_provider"]["name"].s()),
                        bsoncxx::builder::basic::kvp(
                            "icon", body["wallet_provider"]["icon"].s()))))));

    auto result = users.update_one(user_filter.view(), update.view());

    if (result && result->modified_count() > 0) {
      res.code = 200;
      res.body = "Metamask account updated successfully";
    } else {
      res.code = 200;
      res.body = "Metamask account already up-to-date";
    }
    res.end();
    return;

  } catch (const std::exception& e) {
    res.code = 401;
    res.body = std::string("Invalid token: ") + e.what();
    res.end();
    return;
  }
}
