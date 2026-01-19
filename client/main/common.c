#include "common.h"
#include <stdlib.h>
#include <sodium.h>
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "common";

/**
 * @brief Write binary data to NVS.
 * @param key The NVS key (formerly file path).
 * @param data Pointer to the binary data.
 * @param len Length of the binary data.
 * @return 0 on success, -1 on failure.
 */
int nvs_write_blob_str(const char *key, const unsigned char *data, size_t len) {
    nvs_handle_t nvs_handle;
    esp_err_t err;

    // Open NVS handle
    err = nvs_open(NVS_KEY_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
        return -1;
    }

    // Write the blob
    err = nvs_set_blob(nvs_handle, key, data, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) writing blob to NVS!", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return -1;
    }

    // Commit changes
    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) committing NVS!", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return -1;
    }

    nvs_close(nvs_handle);
    return 0;
}

/**
 * @brief Read binary data from NVS.
 * @param key The NVS key (formerly file path).
 * @param data Pointer to the buffer to store the binary data.
 * @param len Expected length of the binary data to read.
 * @return 0 on success, -1 on failure (if key not found or length mismatch).
 */
int nvs_read_blob_str(const char *key, unsigned char *data, size_t max_len) {
    nvs_handle_t nvs_handle;
    esp_err_t err;

    err = nvs_open(NVS_KEY_NAMESPACE, NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        // It is normal for keys to be missing on first run
        if (err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "NVS Open Error (%s) for key: %s", esp_err_to_name(err), key);
        }
        return -1;
    }

    // Get the actual size stored in Flash
    size_t required_size = 0;
    err = nvs_get_blob(nvs_handle, key, NULL, &required_size);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Key not found or error getting size: %s", key);
        nvs_close(nvs_handle);
        return -1;
    }

    // 2. Check buffer capacity
    if (required_size > max_len) {
        ESP_LOGE(TAG, "Buffer too small for %s. Stored: %d, Capacity: %d", key, required_size, max_len);
        nvs_close(nvs_handle);
        return -1;
    }

    // 3. Read the data
    err = nvs_get_blob(nvs_handle, key, data, &required_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error reading blob %s", key);
        nvs_close(nvs_handle);
        return -1;
    }

    // 4. Zero-out the remaining buffer for safety
    if (required_size < max_len) {
        memset(data + required_size, 0, max_len - required_size);
    }

    nvs_close(nvs_handle);
    return 0;
}

/**
 * @brief Check if a key exists in NVS.
 * @param key The NVS key (formerly file path).
 * @return 1 if the key exists, 0 otherwise.
 */
int nvs_key_exists(const char *key) {
    nvs_handle_t nvs_handle;
    esp_err_t err;
    size_t required_len = 0;

    err = nvs_open(NVS_KEY_NAMESPACE, NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        return 0;
    }

    err = nvs_get_blob(nvs_handle, key, NULL, &required_len);
    nvs_close(nvs_handle);

    return (err == ESP_OK && required_len > 0) ? 1 : 0;
}


/**
 * @brief Read a line of input from the serial console (UART).
 * @return Pointer to the allocated string, or NULL on failure.
 * @note Caller must free() the returned string.
 */
char *read_message_from_stdin() {
    size_t capacity = 80;
    size_t len = 0;
    char *buffer = malloc(capacity);
    if (!buffer) {
        ESP_LOGE(TAG, "Failed to allocate buffer for message");
        return NULL;
    }

    while (1) {
        int c = fgetc(stdin);

        if (c < 0) { // Error or timeout
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        if (c == '\n' || c == '\r') {
            printf("\n");
            if (c == '\r') {
                fgetc(stdin); 
            }
            break;
        }

        else if (c == '\b' || c == 0x7F) { // ASCII 8 ('\b') or 127 (Delete)
            if (len > 0) {
                len--; // Move buffer position back
                printf("\b \b");
                fflush(stdout);
            }
        }

        if (c >= 32 && c < 127) { // Printable char
            if (len + 1 >= capacity) {
                // Resize buffer
                capacity *= 2;
                char *new_buffer = realloc(buffer, capacity);
                if (!new_buffer) {
                    ESP_LOGE(TAG, "Failed to realloc message buffer");
                    free(buffer);
                    return NULL;
                }
                buffer = new_buffer;
            }
            buffer[len++] = (char)c;
            printf("%c", (char)c);
            fflush(stdout);
        }
    }

    buffer[len] = '\0'; // Null-terminate
    return buffer;
}


/**
 * @brief Encode binary data to a Base64 string.
 * @param data Pointer to the binary data.
 * @param len Length of the binary data.
 * @return Pointer to allocated Base64 string, or NULL on failure.
 * @note Caller must free() the returned string.
 */
char *b64_encode(const unsigned char *data, size_t len) {
    size_t b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *b64_buf = malloc(b64_len);
    if (!b64_buf) {
        ESP_LOGE(TAG, "malloc failed for b64_encode");
        return NULL;
    }
    sodium_bin2base64(b64_buf, b64_len, data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return b64_buf;
}


/**
 * @brief Decode a Base64 string to binary data.
 * @param b64_str Pointer to the Base64 string.
 * @param data Pointer to the buffer to store decoded binary data.
 * @param data_len Length of the binary data buffer.
 * @return Number of bytes decoded, or 0 on failure.
 */
size_t b64_decode(const char *b64_str, unsigned char *data, size_t data_len) {
    size_t decoded_len = 0;
    if (sodium_base642bin(data, data_len, b64_str, strlen(b64_str),
                          NULL, &decoded_len, NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        ESP_LOGE(TAG, "sodium_base642bin failed");
        return 0;
    }
    return decoded_len;
}


/**
 * @brief Decode a Base64 string to binary data, allocating exact buffer.
 * @param b64_input Pointer to the Base64 string.
 * @param b64_len Length of the Base64 string. If 0, strlen() is used.
 * @param out_len Pointer to store the length of decoded binary data.
 * @return Pointer to allocated binary data, or NULL on failure.
 * @note Caller must free() the returned buffer.
 */
unsigned char *b64_decode_ex(const char *b64_input, size_t b64_len, size_t *out_len) {
    if (b64_input == NULL) {
        ESP_LOGE(TAG, "b64_decode_ex: FATAL: b64_input was NULL.");
        return NULL;
    }
    
    if (b64_len == 0) {
        b64_len = strlen(b64_input);
    }

    if (b64_len == 0) {
        *out_len = 0;
        unsigned char *output = malloc(1);
        if (output) output[0] = '\0';
        return output;
    }

    // 1. Allocate a temporary buffer
    size_t temp_buf_len = b64_len;
    unsigned char *temp_output = malloc(temp_buf_len);
    if (!temp_output) {
        ESP_LOGE(TAG, "b64_decode_ex: malloc failed for temp buffer");
        return NULL;
    }

    // 2. Decode
    size_t bin_len_actual;
    if (sodium_base642bin(temp_output, temp_buf_len,
                          b64_input, b64_len,
                          NULL, &bin_len_actual,
                          NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        ESP_LOGE(TAG, "b64_decode_ex: sodium_base642bin failed. Invalid base64 string?");
        free(temp_output);
        return NULL;
    }

    // 3. Allocate final buffer
    unsigned char *output = malloc(bin_len_actual);
    if (!output) {
        ESP_LOGE(TAG, "b64_decode_ex: malloc failed for final buffer");
        free(temp_output);
        return NULL;
    }

    // 4. Copy and return
    memcpy(output, temp_output, bin_len_actual);
    free(temp_output);
    *out_len = bin_len_actual;
    return output;
}


/**
 * @brief HKDF key derivation function (RFC 5869) using SHA-512.
 * @param okm Pointer to output keying material buffer.
 * @param okm_len Length of the output keying material.
 * @param ikm Pointer to input keying material.
 * @param ikm_len Length of the input keying material.
 * @param info Context and application specific information.
 * @return 0 on success, -1 on failure.
 */
int hkdf(unsigned char *okm, size_t okm_len,
         const unsigned char *ikm, size_t ikm_len,
         const char *info) {
        
    // Get the mbedTLS message digest info for SHA-512
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md_info == NULL) {
        ESP_LOGE(TAG, "Failed to get mbedTLS MD info for SHA-512");
        return -1;
    }

    int ret = mbedtls_hkdf(md_info,
                           NULL, 0,     // No salt
                           ikm, ikm_len,
                           (const unsigned char *)info, strlen(info),
                           okm, okm_len);

    if (ret != 0) {
        ESP_LOGE(TAG, "mbedTLS HKDF failed with error %d", ret);
        return -1;
    }

    return 0;
}


/** 
 * @brief Print data in hex format.
 * @param label Label to print before the hex data.
 * @param data Pointer to the binary data.
 * @param len Length of the binary data.
 */
void print_hex(const char *label, const unsigned char *data, size_t len) {
    // Allocate buffer for hex string
    char *hex_buf = malloc(len * 2 + 1);
    if (!hex_buf) {
        ESP_LOGE(TAG, "Failed to allocate buffer for print_hex()");
        return;
    }
    
    for (size_t i = 0; i < len; ++i) {
        sprintf(hex_buf + (i * 2), "%02x", data[i]);
    }
    hex_buf[len * 2] = '\0';
    
    ESP_LOGI(TAG, "%s: %s", label, hex_buf);
    free(hex_buf);
}