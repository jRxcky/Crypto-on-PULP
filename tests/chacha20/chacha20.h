#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define C20_BLOCKLEN 64

void chacha20_block(uint32_t out[16], uint32_t const key[8], uint32_t counter, uint32_t const nonce[3]);
void chacha20_encrypt(uint8_t *ciphertext, uint8_t const *plaintext, uint32_t const key[8], uint32_t const nonce[3], uint32_t counter);
void chacha20_decrypt(uint8_t *plaintext, uint8_t const *ciphertext, uint32_t const key[8], uint32_t const nonce[3], uint32_t counter);

#endif 