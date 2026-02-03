#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_sntp.h"
#include "esp_wireguard.h"
#include "sodium.h"
#include <xeddsa.h>
#include "common.h"
#include "keys.h"
#include "mqtt_manager.h"

// Required for manual IP assignment
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"

static const char *TAG = "app_main";

// --- WiFi Configuration ---
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
static int s_retry_num = 0;

static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < 5) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "<YOUR_SSID>",
            .password = "<YOUR_PASSWORD>",
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_wifi_set_ps(WIFI_PS_NONE);

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to ap");
    } else {
        ESP_LOGE(TAG, "Failed to connect to ap");
    }
}

// --- NTP Time Sync ---
void obtain_time() {
    ESP_LOGI(TAG, "Initializing SNTP...");
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();

    // Time Zone: Europe/Rome
    setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3", 1);
    tzset();

    int retry = 0;
    const int retry_count = 15;
    while (sntp_get_sync_status() == SNTP_SYNC_STATUS_RESET) {
        ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", retry + 1, retry_count);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        
        retry++;
        if (retry >= retry_count) {
            ESP_LOGE(TAG, "NTP Sync Failed! System time is required for security.");
            ESP_LOGE(TAG, "Restarting device in 3 seconds...");
            vTaskDelay(3000 / portTICK_PERIOD_MS);
            esp_restart();
        }
    }
    
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    ESP_LOGI(TAG, "Time set (Rome): %s", asctime(&timeinfo));
}

// --- WireGuard Setup ---
static wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();
static wireguard_ctx_t wg_ctx = {0};

void start_wireguard() {
    ESP_LOGI(TAG, "Initializing WireGuard...");

    // Basic Config
    wg_config.private_key = WG_PRIVATE_KEY;
    wg_config.endpoint = WG_ENDPOINT_IP;
    wg_config.port = WG_ENDPOINT_PORT;
    wg_config.public_key = WG_SERVER_PUB_KEY;
    wg_config.persistent_keepalive = 25;

    // Routing (Allowed IPs)
    wg_config.allowed_ip = "0.0.0.0"; 
    wg_config.allowed_ip_mask = "0.0.0.0";
    
    // Initialize
    ESP_ERROR_CHECK(esp_wireguard_init(&wg_config, &wg_ctx));

    // Connect
    ESP_LOGI(TAG, "Connecting to WireGuard Server...");
    esp_err_t err = esp_wireguard_connect(&wg_ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WireGuard connect failed: %s", esp_err_to_name(err));
        return;
    }
    
    // Configure Network Interface (lwIP)
    if (wg_ctx.netif == NULL) {
        ESP_LOGE(TAG, "WireGuard interface is NULL after connect!");
        return;
    }

    ip4_addr_t ip_addr, netmask, gw;

    // Use IP Address from keys.h
    ip4addr_aton(WG_LOCAL_IP_ADDR, &ip_addr);
    
    // Netmask: override to Class A (255.0.0.0)
    IP4_ADDR(&netmask, 255, 0, 0, 0);

    // Gateway: Set to VPN Server's IP
    IP4_ADDR(&gw, 10, 13, 13, 1);

    ESP_LOGI(TAG, "Configuring WireGuard Interface IP (lwIP): %s / 255.0.0.0", WG_LOCAL_IP_ADDR);
    
    netif_set_addr(wg_ctx.netif, &ip_addr, &netmask, &gw);
    
    // Lower MTU to prevent packet loss
    wg_ctx.netif->mtu = 1280;

    netif_set_up(wg_ctx.netif);
    ESP_LOGI(TAG, "WireGuard Tunnel is up.");
}

void app_main(void) {
    // 1. Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // 2. Initialize WiFi
    wifi_init_sta();

    // 3. Sync Time
    obtain_time();

    // 4. Start VPN
    start_wireguard();
    ESP_LOGI(TAG, "Waiting for WireGuard tunnel to stabilize...");
    vTaskDelay(pdMS_TO_TICKS(5000));

    // 5. Initialize Crypto (Sodium/XEdDSA)
    if (xeddsa_init() == -1) {
        ESP_LOGE(TAG, "Failed to initialize crypto!");
        return;
    }

    // 6. Start MQTT Client
    ESP_LOGI(TAG, "Starting MQTT Client...");
    mqtt_app_start();
    ESP_LOGI(TAG, "Waiting for MQTT connection...");
    if (!mqtt_wait_for_connection(15000)) { // Wait up to 15 seconds
        ESP_LOGE(TAG, "Failed to connect to MQTT Broker! Check certificates/VPN.");
        return;
    }

    // 7. Run X3DH Menu
    ESP_LOGI(TAG, "Starting X3DH client over VPN...");
    xTaskCreate(run_x3dh_menu, "x3dh_task", 12288, NULL, 5, NULL);
}