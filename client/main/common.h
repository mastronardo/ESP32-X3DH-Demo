#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <xeddsa.h>
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

// X3DH Info Parameter
#define X3DH_INFO_STRING "MyProtocol"

// NVS Namespace for storing keys
// Maximum length is 15 characters
#define NVS_KEY_NAMESPACE "x3dh_keys"

int nvs_write_blob_str(const char *key, const unsigned char *data, size_t len);
int nvs_read_blob_str(const char *key, unsigned char *data, size_t len);
int nvs_key_exists(const char *key);

char *read_message_from_stdin();

char *b64_encode(const unsigned char *data, size_t len);
size_t b64_decode(const char *b64_str, unsigned char *data, size_t data_len);
unsigned char *b64_decode_ex(const char *b64_input, size_t b64_len, size_t *out_len);

int hkdf(unsigned char *okm, size_t okm_len,
         const unsigned char *ikm, size_t ikm_len,
         const char *info);

void run_x3dh_menu();

#endif // COMMON_H