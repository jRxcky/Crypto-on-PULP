#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>
#include <stdint.h>

//Defining Structure
typedef struct poly1305_context {
    uint32_t r[5];                              //Secret key for the Poly1305 algorithm. It’s a 130-bit integer, represented as an array of five 32-bit integers
    uint32_t h[5];                              //Current state of the Poly1305 computation. It’s also a 130-bit integer, represented as an array of five 32-bit integers
    uint32_t pad[4];                            //Padding for the final Poly1305 computation. It’s a 128-bit integer, represented as an array of four 32-bit integers
    size_t leftover;                            //Keeps track of the number of bytes that have been processed in the current block
    unsigned char buffer[16];                   //Buffer for the incoming data (poly1305 algorithm processes data in 16-byte blocks so we need a buffer of this size)
    unsigned char final;                        //flag that indicates whether the final block has been processed
} poly1305_context;


void poly1305_blocks(poly1305_context *ctx, const unsigned char *m, size_t bytes);
void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);
void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);
void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);
void poly1305_auth(unsigned char out[16], const unsigned char *m, size_t inlen, const unsigned char key[32]);

#endif