#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <cJSON.h>
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "common.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mqtt_manager.h"

static const char *TAG = "x3dh_client";

#define SHARED_KEY_SIZE 32
#define SIGNATURE_NONCE_SIZE 64
#define KDF_INPUT_MAX_SIZE 160
#define NUM_OPKS 5 // 5 to save stack/time, increase if needed
#define TOPIC_BUFFER_SIZE 128

// Global buffer to hold the current username in memory to avoid constant NVS reads
static char current_username[32] = {0};

// --- Key Paths (NVS Keys) ---
// Maximum length is 15 characters
#define NVS_KEY_MY_USERNAME "my_username"
#define NVS_KEY_IK_PRIV     "my_ik_priv"
#define NVS_KEY_IK_PUB      "my_ik_pub"
#define NVS_KEY_SPK_PRIV    "my_spk_priv"
#define NVS_KEY_SPK_PUB     "my_spk_pub"
#define NVS_PREFIX_OPK      "opk_"        
#define NVS_PREFIX_SK       "sk_"   

/**
 * @brief Generate a safe, short NVS key for a shared key.
 * @param path_buf Buffer to store the generated path.
 * @param buf_len Length of the buffer.
 * @param peer_name The peer's username.
 * @note Uses a hash of the peer's name to ensure the key length is always < 16 chars.
 */
void get_sk_path(char *path_buf, size_t buf_len, const char *peer_name) {
    unsigned char hash[crypto_generichash_BYTES_MIN];

    // Hash the username
    crypto_generichash(hash, sizeof(hash), (const unsigned char *)peer_name, strlen(peer_name), NULL, 0);

    // Create a key like "sk_A1B2C3D4"
    // We use the first 4 bytes of the hash to create a unique 8-char hex suffix
    snprintf(path_buf, buf_len, "%s%02x%02x%02x%02x", NVS_PREFIX_SK, hash[0], hash[1], hash[2], hash[3]);
}

/**
 * @brief Get the NVS key for the OPK private key.
 * @param path_buf Buffer to store the generated path.
 * @param buf_len Length of the buffer.
 * @param key_id The OPK ID number.
 * @note Format: "opk_1", "opk_2"
 */
void get_opk_path(char *path_buf, size_t buf_len, int key_id) {
    snprintf(path_buf, buf_len, "%s%d", NVS_PREFIX_OPK, key_id);
}

// Ensure we have a username. If not in NVS, ask user.
void ensure_username() {
    // Try to load from NVS first
    if (nvs_read_blob_str(NVS_KEY_MY_USERNAME, (unsigned char *)current_username, sizeof(current_username)) == 0) {
        ESP_LOGI(TAG, "Loaded username from NVS: %s", current_username);
        return;
    }

    // Not found, ask user
    while (1) {
        printf("\n--- Setup ---\nNo username found in flash.\nPlease enter your desired username: ");
        fflush(stdout);
        char *input = read_message_from_stdin();
        if (input && strlen(input) > 0 && strlen(input) < 30) {
            strcpy(current_username, input);
            free(input);
            // Save to NVS
            if (nvs_write_blob_str(NVS_KEY_MY_USERNAME, (unsigned char *)current_username, strlen(current_username) + 1) == 0) {
                ESP_LOGI(TAG, "Username '%s' saved to NVS.", current_username);
                break;
            } else {
                ESP_LOGE(TAG, "Failed to save username to NVS!");
            }
        } else {
            ESP_LOGW(TAG, "Invalid username.");
            if(input) free(input);
        }
    }
}

// --- Menu Command Implementations ---
void cmd_list_users() {
    ESP_LOGI(TAG, "Fetching user list via MQTT...");
    
    // Create empty payload for request
    cJSON *req = cJSON_CreateObject();
    char *resp_str = mqtt_rpc_call("x3dh/req/users", req);
    cJSON_Delete(req);

    if (!resp_str) {
        ESP_LOGE(TAG, "Failed to get user list (Timeout).");
        return;
    }

    cJSON *json = cJSON_Parse(resp_str);
    cJSON *users_array = cJSON_GetObjectItem(json, "users");

    if (cJSON_IsArray(users_array)) {
        printf("\n--- Registered Users ---\n");
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, users_array) {
            if (cJSON_IsString(item)) {
                // Highlight our own name
                if (strcmp(item->valuestring, current_username) == 0) {
                    printf(" * %s (You)\n", item->valuestring);
                } else {
                    printf(" - %s\n", item->valuestring);
                }
            }
        }
        printf("------------------------\n");
    } else {
        ESP_LOGE(TAG, "Invalid JSON received: %s", resp_str);
    }
    
    cJSON_Delete(json);
    free(resp_str);
}

void cmd_register_identity() {
    if (nvs_key_exists(NVS_KEY_IK_PRIV)) {
        ESP_LOGW(TAG, "Identity keys already exist. Skipping generation.");
        // We send the public key to server to ensure registration
    } else {
        ESP_LOGI(TAG, "Generating new Identity Keys...");
        unsigned char ik_priv[crypto_scalarmult_curve25519_BYTES];
        unsigned char ik_pub[crypto_scalarmult_curve25519_BYTES];
        randombytes_buf(ik_priv, sizeof(ik_priv));
        priv_to_curve25519_pub(ik_pub, ik_priv);
        nvs_write_blob_str(NVS_KEY_IK_PRIV, ik_priv, sizeof(ik_priv));
        nvs_write_blob_str(NVS_KEY_IK_PUB, ik_pub, sizeof(ik_pub));
        sodium_memzero(ik_priv, sizeof(ik_priv));
    }

    // Load Public Key
    unsigned char ik_pub[crypto_scalarmult_curve25519_BYTES];
    if (nvs_read_blob_str(NVS_KEY_IK_PUB, ik_pub, sizeof(ik_pub)) != 0) {
        ESP_LOGE(TAG, "Could not read IK Public key.");
        return;
    }

    // Create JSON
    char *ik_pub_b64 = b64_encode(ik_pub, sizeof(ik_pub));
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "username", current_username);
    cJSON_AddStringToObject(req, "ik_b64", ik_pub_b64);
    free(ik_pub_b64);

    // MQTT Call
    char *resp_str = mqtt_rpc_call("x3dh/register/ik", req);
    cJSON_Delete(req);

    if (resp_str) {
        cJSON *res_json = cJSON_Parse(resp_str);
        cJSON *status = cJSON_GetObjectItem(res_json, "status");
        
        if (status && strcmp(status->valuestring, "created") == 0) {
             cJSON *final_name = cJSON_GetObjectItemCaseSensitive(res_json, "username");
             if (cJSON_IsString(final_name) && strcmp(final_name->valuestring, current_username) != 0) {
                // Check if server renamed us (e.g., Bob -> Bob2)
                ESP_LOGW(TAG, "Username '%s' taken. Server assigned: '%s'", current_username, final_name->valuestring);
                strcpy(current_username, final_name->valuestring);
                nvs_write_blob_str(NVS_KEY_MY_USERNAME, (unsigned char *)current_username, strlen(current_username)+1);
             } else {
                ESP_LOGI(TAG, "Identity registered successfully.");
             }
        } else {
            ESP_LOGE(TAG, "Registration failed. Response: %s", resp_str);
        }
        cJSON_Delete(res_json);
        free(resp_str);
    } else {
        ESP_LOGE(TAG, "Registration timeout.");
    }
}

void cmd_publish_bundle() {
    // Load Identity Keys
    unsigned char ik_priv[crypto_scalarmult_curve25519_BYTES];
    if (nvs_read_blob_str(NVS_KEY_IK_PRIV, ik_priv, sizeof(ik_priv)) != 0) {
        ESP_LOGE(TAG, "Register Identity first!");
        return;
    }

    // Generate SPK
    unsigned char spk_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char spk_pub[crypto_scalarmult_curve25519_BYTES];
    randombytes_buf(spk_priv, sizeof(spk_priv));
    priv_to_curve25519_pub(spk_pub, spk_priv);
    
    // Save SPK
    nvs_write_blob_str(NVS_KEY_SPK_PRIV, spk_priv, sizeof(spk_priv));
    nvs_write_blob_str(NVS_KEY_SPK_PUB, spk_pub, sizeof(spk_pub));

    // Sign SPK
    unsigned char signature[crypto_sign_ed25519_BYTES];
    uint8_t sign_nonce[SIGNATURE_NONCE_SIZE];
    randombytes_buf(sign_nonce, SIGNATURE_NONCE_SIZE);
    
    unsigned char signing_key[crypto_scalarmult_curve25519_BYTES];
    priv_force_sign(signing_key, ik_priv, 0); // Convert X25519 priv to Ed25519 signing key
    ed25519_priv_sign(signature, signing_key, spk_pub, sizeof(spk_pub), sign_nonce);
    
    // Generate OPKs
    cJSON *opks_array = cJSON_CreateArray();
    for(int i=0; i<NUM_OPKS; i++) {
        unsigned char opk_priv[32], opk_pub[32];
        randombytes_buf(opk_priv, 32);
        priv_to_curve25519_pub(opk_pub, opk_priv);
        
        char path[32];
        get_opk_path(path, sizeof(path), i);
        nvs_write_blob_str(path, opk_priv, 32);
        
        char *b64 = b64_encode(opk_pub, 32);
        cJSON *opk_obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(opk_obj, "id", i);
        cJSON_AddStringToObject(opk_obj, "key", b64);
        cJSON_AddItemToArray(opks_array, opk_obj);
        free(b64);
    }

    // Upload
    char *spk_b64 = b64_encode(spk_pub, 32);
    char *sig_b64 = b64_encode(signature, sizeof(signature));

    cJSON *bundle = cJSON_CreateObject();
    cJSON_AddStringToObject(bundle, "username", current_username);
    cJSON_AddStringToObject(bundle, "spk_b64", spk_b64);
    cJSON_AddStringToObject(bundle, "spk_sig_b64", sig_b64);
    cJSON_AddItemToObject(bundle, "opks_b64", opks_array);

    char *resp_str = mqtt_rpc_call("x3dh/register/bundle", bundle);
    
    if (resp_str) {
        ESP_LOGI(TAG, "Bundle publish response: %s", resp_str);
        free(resp_str);
    } else {
        ESP_LOGE(TAG, "Bundle publish timeout.");
    }

    free(spk_b64);
    free(sig_b64);
    cJSON_Delete(bundle);
    sodium_memzero(ik_priv, sizeof(ik_priv));
    sodium_memzero(spk_priv, sizeof(spk_priv));
    sodium_memzero(signing_key, sizeof(signing_key));
}

void cmd_init_chat() {
    cmd_list_users();
    printf("Enter name of peer to chat with: ");
    fflush(stdout);
    char *recipient = read_message_from_stdin();
    if (!recipient || strlen(recipient) == 0) {
        if(recipient) free(recipient);
        return;
    }

    ESP_LOGI(TAG, "Requesting bundle for %s...", recipient);

    // Get Bundle (Construct Topic: x3dh/req/bundle/<username>)
    char topic[TOPIC_BUFFER_SIZE];
    snprintf(topic, sizeof(topic), "x3dh/req/bundle/%s", recipient);
    
    cJSON *empty_req = cJSON_CreateObject();
    char *resp_str = mqtt_rpc_call(topic, empty_req);
    cJSON_Delete(empty_req);

    if (!resp_str) {
        ESP_LOGE(TAG, "Failed to get bundle.");
        free(recipient); return;
    }

    cJSON *json = cJSON_Parse(resp_str);
    if (!json || cJSON_HasObjectItem(json, "error")) {
        ESP_LOGE(TAG, "Error fetching bundle: %s", resp_str);
        free(resp_str); cJSON_Delete(json); free(recipient);
        return;
    }
    free(resp_str); // Done with string, keep JSON

    // Extract Keys
    const char *peer_ik_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(json, "ik_b64"));
    const char *peer_spk_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(json, "spk_b64"));
    const char *peer_sig_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(json, "spk_sig_b64"));
    const char *peer_opk_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(json, "opk_b64"));
    int opk_id = -1;
    if (cJSON_GetObjectItem(json, "opk_id")) opk_id = cJSON_GetObjectItem(json, "opk_id")->valueint;

    if (!peer_ik_b64 || !peer_spk_b64) {
        ESP_LOGE(TAG, "Invalid bundle data");
        cJSON_Delete(json); free(recipient); return;
    }

    unsigned char peer_ik[32], peer_spk[32], peer_sig[64], peer_opk[32];
    b64_decode(peer_ik_b64, peer_ik, 32);
    b64_decode(peer_spk_b64, peer_spk, 32);
    b64_decode(peer_sig_b64, peer_sig, 64);
    int has_opk = (peer_opk_b64 != NULL);
    if (has_opk) b64_decode(peer_opk_b64, peer_opk, 32);

    // Verify Sig
    unsigned char ed_peer_ik[32];
    curve25519_pub_to_ed25519_pub(ed_peer_ik, peer_ik, 0);
    if (ed25519_verify(peer_sig, ed_peer_ik, peer_spk, 32) != 0) {
        ESP_LOGE(TAG, "Invalid SPK signature!");
        free(recipient); cJSON_Delete(json); return;
    }

    // Load My Keys
    unsigned char my_ik_priv[32], my_ik_pub[32];
    nvs_read_blob_str(NVS_KEY_IK_PRIV, my_ik_priv, 32);
    nvs_read_blob_str(NVS_KEY_IK_PUB, my_ik_pub, 32);

    // Generate EK
    unsigned char ek_priv[32], ek_pub[32];
    randombytes_buf(ek_priv, 32);
    priv_to_curve25519_pub(ek_pub, ek_priv);

    // Calculate DH
    unsigned char dh1[32], dh2[32], dh3[32], dh4[32];
    x25519(dh1, my_ik_priv, peer_spk);
    x25519(dh2, ek_priv, peer_ik);
    x25519(dh3, ek_priv, peer_spk);
    
    unsigned char kdf_input[160];
    memset(kdf_input, 0xFF, 32); // F padding
    memcpy(kdf_input+32, dh1, 32);
    memcpy(kdf_input+64, dh2, 32);
    memcpy(kdf_input+96, dh3, 32);
    size_t kdf_len = 128;

    if (has_opk) {
        x25519(dh4, ek_priv, peer_opk);
        memcpy(kdf_input+128, dh4, 32);
        kdf_len += 32;
    }

    unsigned char sk[SHARED_KEY_SIZE];
    hkdf(sk, sizeof(sk), kdf_input, kdf_len, X3DH_INFO_STRING);
    
    // Save SK
    char sk_path[64];
    get_sk_path(sk_path, sizeof(sk_path), recipient);
    nvs_write_blob_str(sk_path, sk, sizeof(sk));
    ESP_LOGI(TAG, "Shared Key calculated.");

    // Encrypt Initial Message
    printf("Enter initial message for %s: ", recipient);
    fflush(stdout);
    char *msg_txt = read_message_from_stdin();
    
    unsigned char ad[64];
    memcpy(ad, my_ik_pub, 32);
    memcpy(ad+32, peer_ik, 32);
    
    unsigned char nonce[24];
    randombytes_buf(nonce, 24);
    
    size_t ct_len = strlen(msg_txt) + 16; // 16 = poly1305 tag
    unsigned char *ct = malloc(ct_len);
    unsigned long long ct_len_actual;
    crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &ct_len_actual, (unsigned char*)msg_txt, strlen(msg_txt), ad, 64, NULL, nonce, sk);

    // Send via MQTT
    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "to", recipient);
    cJSON_AddStringToObject(payload, "from", current_username);

    char *tmp = b64_encode(my_ik_pub, 32);
    cJSON_AddStringToObject(payload, "ik_b64", tmp);
    free(tmp);

    tmp = b64_encode(ek_pub, 32);
    cJSON_AddStringToObject(payload, "ek_b64", tmp);
    free(tmp);

    tmp = b64_encode(ct, ct_len_actual);
    cJSON_AddStringToObject(payload, "ciphertext_b64", tmp);
    free(tmp);

    tmp = b64_encode(ad, 64);
    cJSON_AddStringToObject(payload, "ad_b64", tmp);
    free(tmp);

    tmp = b64_encode(nonce, 24);
    cJSON_AddStringToObject(payload, "nonce_b64", tmp);
    free(tmp);

    cJSON_AddNumberToObject(payload, "opk_id", has_opk ? opk_id : -1);

    resp_str = mqtt_rpc_call("x3dh/msg/init", payload);
    if (resp_str) {
        ESP_LOGI(TAG, "Initial message sent response: %s", resp_str);
        free(resp_str);
    } else {
        ESP_LOGE(TAG, "Failed to send initial message (Timeout).");
    }

    free(recipient);
    free(msg_txt);
    free(ct);
    cJSON_Delete(payload);
    cJSON_Delete(json);
    sodium_memzero(my_ik_priv, 32);
    sodium_memzero(ek_priv, 32);
    sodium_memzero(sk, 32);
}

void cmd_check_inbox() {
    // Topic: x3dh/req/inbox/<my_username>
    char topic[TOPIC_BUFFER_SIZE];
    snprintf(topic, sizeof(topic), "x3dh/req/inbox/%s", current_username);

    cJSON *empty = cJSON_CreateObject();
    char *resp_str = mqtt_rpc_call(topic, empty);
    cJSON_Delete(empty);

    if (!resp_str) {
        ESP_LOGE(TAG, "Inbox check timeout.");
        return;
    }

    cJSON *json = cJSON_Parse(resp_str);
    free(resp_str);

    if (!json || cJSON_HasObjectItem(json, "error")) {
        ESP_LOGI(TAG, "No new X3DH requests.");
        cJSON_Delete(json);
        return;
    }

    const char *from = cJSON_GetStringValue(cJSON_GetObjectItem(json, "from_user"));
    const char *ik_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(json, "ik_b64"));
    const char *ek_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(json, "ek_b64"));
    const char *ct_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(json, "ciphertext_b64"));
    const char *ad_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(json, "ad_b64"));
    const char *nc_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(json, "nonce_b64"));
    int opk_id = cJSON_GetObjectItem(json, "opk_id")->valueint;

    ESP_LOGI(TAG, "Handshake received from %s", from);

    unsigned char peer_ik[32], peer_ek[32], ad[64], nonce[24];
    b64_decode(ik_b64, peer_ik, 32);
    b64_decode(ek_b64, peer_ek, 32);
    b64_decode(ad_b64, ad, 64);
    b64_decode(nc_b64, nonce, 24);

    // Load My Keys
    unsigned char my_ik_priv[32], my_spk_priv[32], my_opk_priv[32];
    nvs_read_blob_str(NVS_KEY_IK_PRIV, my_ik_priv, 32);
    nvs_read_blob_str(NVS_KEY_SPK_PRIV, my_spk_priv, 32);
    
    int use_opk = (opk_id != -1);
    char opk_path[32];
    if (use_opk) {
        get_opk_path(opk_path, sizeof(opk_path), opk_id);
        nvs_read_blob_str(opk_path, my_opk_priv, 32);
    }

    // Calculate DH
    unsigned char dh1[32], dh2[32], dh3[32], dh4[32];
    x25519(dh1, my_spk_priv, peer_ik);
    x25519(dh2, my_ik_priv, peer_ek);
    x25519(dh3, my_spk_priv, peer_ek);
    
    unsigned char kdf_input[160];
    memset(kdf_input, 0xFF, 32);
    memcpy(kdf_input+32, dh1, 32);
    memcpy(kdf_input+64, dh2, 32);
    memcpy(kdf_input+96, dh3, 32);
    size_t kdf_len = 128;

    if (use_opk) {
        x25519(dh4, my_opk_priv, peer_ek);
        memcpy(kdf_input+128, dh4, 32);
        kdf_len += 32;
    }

    unsigned char sk[SHARED_KEY_SIZE];
    hkdf(sk, sizeof(sk), kdf_input, kdf_len, X3DH_INFO_STRING);

    // Save SK
    char sk_path[64];
    get_sk_path(sk_path, sizeof(sk_path), from);
    nvs_write_blob_str(sk_path, sk, sizeof(sk));
    ESP_LOGI(TAG, "Handshake accepted.");

    // Decrypt
    size_t ct_len;
    unsigned char *ct = b64_decode_ex(ct_b64, 0, &ct_len);
    unsigned char *pt = malloc(ct_len);
    unsigned long long pt_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &pt_len, NULL, ct, ct_len, ad, 64, nonce, sk) == 0) {
        pt[pt_len] = '\0';
        printf("--- Message from %s ---\n%s\n-----------------------\n", from, (char*)pt);
    } else {
        ESP_LOGE(TAG, "Decryption failed!");
    }

    // Delete used OPK
    if (use_opk) {
        nvs_handle_t h; 
        nvs_open(NVS_KEY_NAMESPACE, NVS_READWRITE, &h);
        nvs_erase_key(h, opk_path);
        nvs_commit(h);
        nvs_close(h);
    }

    free(ct); free(pt);
    cJSON_Delete(json);
    sodium_memzero(sk, 32); sodium_memzero(my_ik_priv, 32);
}

void cmd_chat(int mode) {
    // mode 0 = send, mode 1 = receive
    cmd_list_users();
    printf("Enter name of peer: ");
    fflush(stdout);
    char *peer = read_message_from_stdin();
    if (!peer) return;

    char sk_path[64];
    get_sk_path(sk_path, sizeof(sk_path), peer);
    unsigned char sk[32];

    if (nvs_read_blob_str(sk_path, sk, 32) != 0) {
        ESP_LOGE(TAG, "No shared key with %s. Do 'Init Chat' or 'Check Inbox' first.", peer);
        free(peer); return;
    }

    if (mode == 0) {
        printf("Message: "); fflush(stdout);
        char *txt = read_message_from_stdin();
        unsigned char nonce[24]; randombytes_buf(nonce, 24);
        size_t ct_len = strlen(txt) + 16;
        unsigned char *ct = malloc(ct_len);
        unsigned long long actual_len;
        
        crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &actual_len, (unsigned char*)txt, strlen(txt), NULL, 0, NULL, nonce, sk);
        
        char *b64_ct = b64_encode(ct, actual_len);
        char *b64_nc = b64_encode(nonce, 24);
        
        cJSON *req = cJSON_CreateObject();
        cJSON_AddStringToObject(req, "from", current_username);
        cJSON_AddStringToObject(req, "to", peer);
        cJSON_AddStringToObject(req, "ciphertext_b64", b64_ct);
        cJSON_AddStringToObject(req, "nonce_b64", b64_nc);

        char *resp_str = mqtt_rpc_call("x3dh/msg/chat", req);
        if (resp_str) {
            ESP_LOGI(TAG, "Message sent.");
            free(resp_str);
        } else {
            ESP_LOGE(TAG, "Send timeout.");
        }
        
        free(txt); free(ct); free(b64_ct); free(b64_nc); cJSON_Delete(req);
    }
    else {
        // Request payload for server to filter messages
        cJSON *req = cJSON_CreateObject();
        cJSON_AddStringToObject(req, "to", current_username);
        cJSON_AddStringToObject(req, "from", peer);
        
        char *resp_str = mqtt_rpc_call("x3dh/req/chat", req);
        cJSON_Delete(req);

        if (resp_str) {
            cJSON *arr = cJSON_Parse(resp_str);
            if (cJSON_IsArray(arr)) {
                int count = 0;
                cJSON *item;
                cJSON_ArrayForEach(item, arr) {
                    const char *ct_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(item, "ciphertext_b64"));
                    const char *nc_b64 = cJSON_GetStringValue(cJSON_GetObjectItem(item, "nonce_b64"));
                    size_t ct_len;
                    unsigned char *ct = b64_decode_ex(ct_b64, 0, &ct_len);
                    unsigned char nonce[24]; b64_decode(nc_b64, nonce, 24);
                    unsigned char *pt = malloc(ct_len);
                    unsigned long long pt_len;
                    
                    if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &pt_len, NULL, ct, ct_len, NULL, 0, nonce, sk) == 0) {
                        pt[pt_len] = 0;
                        printf("[%s]: %s\n", peer, (char*)pt);
                        count++;
                    }
                    free(ct); free(pt);
                }
                if (count == 0) ESP_LOGI(TAG, "No new messages from %s", peer);
            }
            cJSON_Delete(arr);
            free(resp_str);
        } else {
            ESP_LOGE(TAG, "Failed to fetch messages.");
        }
    }
    free(peer);
    sodium_memzero(sk, 32);
}

// --- Main Menu Loop ---
void run_x3dh_menu() {
    ensure_username();
    char *cmd_buf = NULL;
    
    while(1) {
        printf("\n=========================================\n");
        printf(" User: %s\n", current_username);
        printf("=========================================\n");
        printf(" (1) Register Identity\n");
        printf(" (2) Publish Bundle\n");
        printf(" (3) List Users\n");
        printf(" (4) Start Chat (Init X3DH)\n");
        printf(" (5) Check Inbox (Accept X3DH)\n");
        printf(" (6) Send Message\n");
        printf(" (7) Read Messages\n");
        printf(" (r) Reset Username\n");
        printf(" Enter choice: ");
        fflush(stdout);

        cmd_buf = read_message_from_stdin();
        if (!cmd_buf || strlen(cmd_buf) == 0) { free(cmd_buf); continue; }
        
        char c = cmd_buf[0];
        free(cmd_buf);

        switch(c) {
            case '1': cmd_register_identity(); break;
            case '2': cmd_publish_bundle(); break;
            case '3': cmd_list_users(); break;
            case '4': cmd_init_chat(); break;
            case '5': cmd_check_inbox(); break;
            case '6': cmd_chat(0); break;
            case '7': cmd_chat(1); break;
            case 'r': 
                nvs_handle_t h; nvs_open(NVS_KEY_NAMESPACE, NVS_READWRITE, &h);
                nvs_erase_key(h, NVS_KEY_MY_USERNAME); nvs_commit(h); nvs_close(h);
                ESP_LOGW(TAG, "Username erased. Restarting...");
                esp_restart();
                break;
            default: ESP_LOGW(TAG, "Unknown command."); break;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}