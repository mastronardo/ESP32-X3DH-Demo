#ifndef MQTT_MANAGER_H
#define MQTT_MANAGER_H

#include <cJSON.h>

char* mqtt_rpc_call(const char* topic, cJSON *payload);
void mqtt_app_start(void);
bool mqtt_wait_for_connection(uint32_t timeout_ms);

#endif // MQTT_MANAGER_H