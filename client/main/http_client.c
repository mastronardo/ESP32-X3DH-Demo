#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "esp_http_client.h"
#include "http_client.h"
#include <cJSON.h>

static const char *TAG = "http_client";

/**
 * @brief Initialize a ResponseInfo struct.
 * @param resp Pointer to ResponseInfo struct to initialize.
 */
static void init_response(ResponseInfo *resp) {
    resp->size = 0;
    resp->body = malloc(1); // Start with 1 byte
    if (resp->body) {
        resp->body[0] = '\0';
    }
    resp->http_code = 0;
}

/**
 * @brief Free the memory allocated for the response body.
 * @param resp Pointer to ResponseInfo struct to clean up.
 */
void cleanup_response(ResponseInfo *resp) {
    if (resp->body) {
        free(resp->body);
        resp->body = NULL;
    }
    resp->size = 0;
}

/**
 * @brief Event handler for esp_http_client.
 * @param evt Pointer to esp_http_client_event_t structure.
 * @return esp_err_t ESP_OK on success, ESP_FAIL on failure.
 */
static esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    ResponseInfo *resp_info = (ResponseInfo *)evt->user_data;

    switch(evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            if (resp_info) {
                // Reallocate buffer
                char *ptr = realloc(resp_info->body, resp_info->size + evt->data_len + 1);
                if (ptr == NULL) {
                    ESP_LOGE(TAG, "Failed to realloc memory for HTTP response");
                    return ESP_FAIL;
                }
                resp_info->body = ptr;
                // Copy new data
                memcpy(resp_info->body + resp_info->size, evt->data, evt->data_len);
                resp_info->size += evt->data_len;
                resp_info->body[resp_info->size] = '\0'; // Null-terminate
            }
            break;
        default:
            break;
    }
    return ESP_OK;
}

/**
 * @brief Perform an HTTP GET request.
 * @param url The URL to send the GET request to.
 * @param resp_info Pointer to ResponseInfo struct to store the response.
 * @return int 0 on success, -1 on failure.
 * @note Caller is responsible for freeing the response info.
 */
int http_get(const char *url, ResponseInfo *resp_info) {
    init_response(resp_info);

    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handler,
        .user_data = resp_info,
        .disable_auto_redirect = false,
        .timeout_ms = 30000,        // Keep the 30s timeout
        .keep_alive_enable = false, // Force new connection
    };
    
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        return -1;
    }
    
    // Explicitly tell server to close socket after reply
    esp_http_client_set_header(client, "Connection", "close"); 
    esp_http_client_set_header(client, "Cache-Control", "no-cache");

    esp_err_t err = ESP_FAIL;
    for (int i = 0; i < 3; i++) {
        err = esp_http_client_perform(client);
        if (err == ESP_OK) {
            break; // Success!
        }
        ESP_LOGW(TAG, "HTTP GET failed (attempt %d/3): %s. Retrying...", i+1, esp_err_to_name(err));
        vTaskDelay(pdMS_TO_TICKS(1000)); // Wait 1 second before retrying
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP GET request failed after 3 attempts: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return -1;
    }

    resp_info->http_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    
    ESP_LOGD(TAG, "GET request to %s finished with code %ld, body size %zu", url, resp_info->http_code, resp_info->size);

    return 0;
}


/**
 * @brief Perform an HTTP POST request with a cJSON payload.
 * @param url The URL to send the POST request to.
 * @param payload The cJSON object to send as the POST body.
 * @param resp_info Pointer to ResponseInfo struct to store the response.
 * @return int 0 on success, -1 on failure.
 * @note Caller is responsible for freeing the cJSON payload and the response info.
 */
int http_post_json(const char *url, cJSON *payload, ResponseInfo *resp_info) {
    init_response(resp_info);

    char *payload_str = cJSON_PrintUnformatted(payload);
    if (!payload_str) {
        ESP_LOGE(TAG, "Failed to print cJSON payload");
        return -1;
    }

    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handler,
        .user_data = resp_info,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 30000,
        .keep_alive_enable = false,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        cJSON_free(payload_str);
        return -1;
    }

    // Set headers and post data
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Connection", "close");
    esp_http_client_set_post_field(client, payload_str, strlen(payload_str));

    esp_err_t err = ESP_FAIL;
    for (int i = 0; i < 3; i++) {
        err = esp_http_client_perform(client);
        if (err == ESP_OK) {
            break; // Success!
        }
        ESP_LOGW(TAG, "HTTP POST failed (attempt %d/3): %s. Retrying...", i+1, esp_err_to_name(err));
        vTaskDelay(pdMS_TO_TICKS(1000)); 
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP POST request failed after 3 attempts: %s", esp_err_to_name(err));
        cJSON_free(payload_str);
        esp_http_client_cleanup(client);
        return -1;
    }

    resp_info->http_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    cJSON_free(payload_str);

    ESP_LOGD(TAG, "POST request to %s finished with code %ld, body size %zu", url, resp_info->http_code, resp_info->size);
    return 0;
}