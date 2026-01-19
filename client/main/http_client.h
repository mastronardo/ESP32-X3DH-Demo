#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <cJSON.h>

// VIA VPN: We access the Flask container directly on its internal Docker IP
#define SERVER_URL "http://10.10.0.5:5001"

// Struct to hold the response from an HTTP request
typedef struct {
    char *body;
    size_t size;
    long http_code;
} ResponseInfo;

int http_get(const char *url, ResponseInfo *resp_info);
int http_post_json(const char *url, cJSON *payload, ResponseInfo *resp_info);
void cleanup_response(ResponseInfo *resp);

#endif // HTTP_CLIENT_H