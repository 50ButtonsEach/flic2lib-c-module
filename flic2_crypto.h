/**
 *  Flic 2 C module
 *
 *  Copyright (C) 2022 Shortcut Labs AB
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef FLIC2_CRYPTO_H
#define FLIC2_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void curve25519(uint8_t out[32], const uint8_t point[32], const uint8_t scalar[32]);
bool ed25519_verify(const uint8_t signature[64], const uint8_t* message, uint32_t msg_len, uint8_t* correct_bits);
void chaskey_generate_subkeys(uint32_t k[12], const uint8_t key[16]);
void chaskey_with_dir_and_packet_counter(uint8_t out[5], uint32_t keys[12], int dir, uint64_t counter, const uint8_t* data, uint32_t len);
void chaskey_16_bytes(uint32_t out[4], const uint32_t *keys, const uint32_t data[4]);

typedef struct {
    uint32_t current_hash[8];
    union {
        uint32_t as_uint32[64 / 4];
        uint8_t as_bytes[64];
    } unprocessed;
    uint64_t num_bytes;
} SHA256_STATE;

// Inits a SHA256_STATE
void sha256_init(SHA256_STATE* state);

// Adds a value to the hash state
void sha256_update(SHA256_STATE* state, const uint8_t* value, size_t len);

// Outputs the SHA256 hash of the data given to the sha256_update function
void sha256_finish(SHA256_STATE* state, uint8_t hash[32]);

// HMAC-SHA-256 where key length must be at most 64 bytes
void HMACSHA256(const uint8_t* key, size_t key_len, const uint8_t* message, size_t msg_len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
