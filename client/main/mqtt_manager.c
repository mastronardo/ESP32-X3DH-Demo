#include "mqtt_client.h"
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "cJSON.h"
#include "keys.h"

static const char *TAG = "mqtt";
esp_mqtt_client_handle_t client = NULL;

static EventGroupHandle_t s_mqtt_event_group;
static const int MQTT_CONNECTED_BIT = BIT0;

// Synchronization for Request-Response
static SemaphoreHandle_t s_response_sem;
static char *s_response_buffer = NULL;
static char s_correlation_id[32];

/**
 * @brief Wait for MQTT connection to be established.
 * @param timeout_ms Maximum time to wait in milliseconds.
 * @return true if connected, false on timeout.
 */
bool mqtt_wait_for_connection(uint32_t timeout_ms) {
    EventBits_t bits = xEventGroupWaitBits(s_mqtt_event_group, 
                                           MQTT_CONNECTED_BIT, 
                                           pdFALSE, 
                                           pdTRUE, 
                                           pdMS_TO_TICKS(timeout_ms));
    return (bits & MQTT_CONNECTED_BIT) != 0;
}

/**
 * @brief MQTTv5 event handler.
 * @param base Event base.
 * @param event_id Event ID.
 * @param event_data Event data.
 */
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = event_data;
    switch (event->event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT Connected");
            xEventGroupSetBits(s_mqtt_event_group, MQTT_CONNECTED_BIT);
            // Ensure we subscribe to the response topic
            esp_mqtt_client_subscribe(client, "x3dh/resp/#", 0);
            break;
            
        case MQTT_EVENT_DATA:
            // Validates property existence before access
            if (event->property && event->property->correlation_data && event->property->correlation_data_len > 0) {
                // strict length check + memory compare
                if (event->property->correlation_data_len == strlen(s_correlation_id) &&
                    memcmp(s_correlation_id, event->property->correlation_data, event->property->correlation_data_len) == 0) {
                    
                    if (s_response_buffer) free(s_response_buffer);
                    s_response_buffer = malloc(event->data_len + 1);
                    // Store response and signal waiting task
                    if (s_response_buffer) {
                        memcpy(s_response_buffer, event->data, event->data_len);
                        s_response_buffer[event->data_len] = 0;
                        xSemaphoreGive(s_response_sem);
                    }
                }
            }
            break;

        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT Disconnected");
            xEventGroupClearBits(s_mqtt_event_group, MQTT_CONNECTED_BIT);
            break;
        
        default: break;
    }
}

/**
 * @brief Start the MQTT client.
 */
void mqtt_app_start(void) {
    s_response_sem = xSemaphoreCreateBinary();
    s_mqtt_event_group = xEventGroupCreate();

    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = MQTT_BROKER_URI,
        .broker.verification.certificate = MQTT_CA_CERT_PEM,
        .broker.verification.skip_cert_common_name_check = true,
        .session.protocol_ver = MQTT_PROTOCOL_V_5,
    };

    client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);
}

/**
 * @brief Perform an MQTT RPC call with correlation ID and wait for response.
 * @param topic MQTT topic to publish to.
 * @param payload JSON payload to send.
 * @return Response string on success, NULL on failure or timeout.
 */
char* mqtt_rpc_call(const char* topic, cJSON *payload) {
    // Generate Correlation ID
    snprintf(s_correlation_id, sizeof(s_correlation_id), "%lu", (unsigned long)esp_random());
    
    // Configure Properties for the next message
    esp_mqtt5_publish_property_config_t props = {
        .correlation_data = s_correlation_id,
        .correlation_data_len = strlen(s_correlation_id),
        .response_topic = "x3dh/resp/me",
        .payload_format_indicator = 1,
        .content_type = "application/json"
    };

    // Apply properties
    esp_err_t err = esp_mqtt5_client_set_publish_property(client, &props);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set MQTT properties: %s", esp_err_to_name(err));
        return NULL;
    }

    // Publish the message
    char *json_str = cJSON_PrintUnformatted(payload);
    ESP_LOGI(TAG, "Publishing RPC to %s (CorrID: %s)", topic, s_correlation_id);
    int msg_id = esp_mqtt_client_publish(client, topic, json_str, 0, 1, 0);
    free(json_str);
    if (msg_id == -1) {
         ESP_LOGE(TAG, "Failed to publish message");
         return NULL;
    }

    // Wait for response
    if (xSemaphoreTake(s_response_sem, pdMS_TO_TICKS(10000)) == pdTRUE) {
        char *ret = strdup(s_response_buffer);
        free(s_response_buffer); s_response_buffer = NULL;
        return ret;
    }
    
    ESP_LOGE(TAG, "RPC Timeout");
    return NULL;
}