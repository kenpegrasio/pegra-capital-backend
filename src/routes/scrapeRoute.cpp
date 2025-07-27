#include<string>
#include<curl/curl.h>

std::string get_request(std::string url) {
  // initialize curl locally
  CURL *curl = curl_easy_init();
  std::string result;

  return result;
}
