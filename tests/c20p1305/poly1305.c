/*POLY1305*/

#include "poly1305.h"

//Defining Macros
#define poly1305_block_size 16

//Defining conversion function
static unsigned long U8TO32(const unsigned char *p) {
	return
		(((unsigned long)(p[0] & 0xff)      ) |
	     ((unsigned long)(p[1] & 0xff) <<  8) |
         ((unsigned long)(p[2] & 0xff) << 16) |
         ((unsigned long)(p[3] & 0xff) << 24));
}

static void U32TO8(unsigned char *p, unsigned long v) {
	p[0] = (v      ) & 0xff;
	p[1] = (v >>  8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

uint32_t get_le32(const uint8_t *data) {
    return ((uint32_t)data[0]) |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}


//Defining Main Functions for Poly1305
void poly1305_init(poly1305_context *ctx, const uint8_t key[32]) {        //initialize the context with a given key
	
	//Taking the first 16byte of the key, splitting the key (provided in LE) in 5 blocks of 26 bits (to prevent overflow)
    ctx->r[0] = (get_le32(key +  0)     ) & 0x3ffffff;
    ctx->r[1] = (get_le32(key +  3) >> 2) & 0x3ffff03;
    ctx->r[2] = (get_le32(key +  6) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (get_le32(key +  9) >> 6) & 0x3f03fff;
    ctx->r[4] = (get_le32(key + 12) >> 8) & 0x00fffff;

    //Initializing the "h" (current state) to 0
    for (int i = 0; i < 5; i++)
        ctx->h[i] = 0;

    //Taking the last 16byte of the key
    for (int i = 0; i < 4; i++)
        ctx->pad[i] = get_le32(key + 16 + i*4);
	
	//Initializing the leftover and the final to 0
    ctx->leftover = 0;
    ctx->final = 0;
}



void poly1305_blocks(poly1305_context *ctx, const unsigned char *m, size_t bytes) {
	//Clamping: if ctx->final is true (final block has been processed), hibit is set to 0 else the 25bit is set to 1
    const uint32_t hibit = (ctx->final) ? 0 : (1 << 24);  

	//Var declaration:
    uint32_t r0,r1,r2,r3,r4;
    uint32_t s1,s2,s3,s4;
    uint32_t h0,h1,h2,h3,h4;
    uint64_t d0,d1,d2,d3,d4;
    uint32_t c;

    r0 = ctx->r[0];
    r1 = ctx->r[1];
    r2 = ctx->r[2];
    r3 = ctx->r[3];
    r4 = ctx->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];


    while (bytes >= poly1305_block_size) {			 //(This loop continues as long as there are enough bytes left to form a complete block for the Poly1305 algorithm)
		//Adding the input message m to the current state h (taking only the first 26bits)
		h0 += (U8TO32(m+ 0)     ) & 0x3ffffff;
		h1 += (U8TO32(m+ 3) >> 2) & 0x3ffffff;
		h2 += (U8TO32(m+ 6) >> 4) & 0x3ffffff;
		h3 += (U8TO32(m+ 9) >> 6) & 0x3ffffff;
		h4 += (U8TO32(m+12) >> 8) | hibit;			//Including hibit to differentiate from intermediate and final blocks

		//Core multiplication operation of the Poly1305 algorithm: multiplies the current state h by the key r in a specific pattern and stores the result in d
		d0 = ((unsigned long long)h0 * r0) + ((unsigned long long)h1 * s4) + ((unsigned long long)h2 * s3) + ((unsigned long long)h3 * s2) + ((unsigned long long)h4 * s1);
		d1 = ((unsigned long long)h0 * r1) + ((unsigned long long)h1 * r0) + ((unsigned long long)h2 * s4) + ((unsigned long long)h3 * s3) + ((unsigned long long)h4 * s2);
		d2 = ((unsigned long long)h0 * r2) + ((unsigned long long)h1 * r1) + ((unsigned long long)h2 * r0) + ((unsigned long long)h3 * s4) + ((unsigned long long)h4 * s3);
		d3 = ((unsigned long long)h0 * r3) + ((unsigned long long)h1 * r2) + ((unsigned long long)h2 * r1) + ((unsigned long long)h3 * r0) + ((unsigned long long)h4 * s4);
		d4 = ((unsigned long long)h0 * r4) + ((unsigned long long)h1 * r3) + ((unsigned long long)h2 * r2) + ((unsigned long long)h3 * r1) + ((unsigned long long)h4 * r0);

		//Reducing the h values modulo p where p is 2^130 - 5:
		// 1. A right shift operation is performed on d0 by 26 bits. The result is stored in the variable c
		c = (unsigned long)(d0 >> 26); 
		// 2. The lower 26 bits of d0 are stored in h0
		h0 = (unsigned long)d0 & 0x3ffffff; 
		// The same operations are repeated for d1, d2, d3, and d4.
		d1 += c;      c = (unsigned long)(d1 >> 26); h1 = (unsigned long)d1 & 0x3ffffff;
		d2 += c;		c = (unsigned long)(d2 >> 26);		h2 = (unsigned long)d2 & 0x3ffffff;
		d3 += c;		c = (unsigned long)(d3 >> 26);		h3 = (unsigned long)d3 & 0x3ffffff;
		d4 += c;        c = (unsigned long)(d4 >> 26);		h4 = (unsigned long)d4 & 0x3ffffff;

		// 3. (additional operation is performed on h0): he value of c (carry from the previous operation) is multiplied by 5 and added to h0
		h0 += c * 5;  
		// 4. A right shift operation is performed on h0 by 26 bits. The result is stored in the variable c
		c = (h0 >> 26); 
		// 5. The lower 26 bits of h0 are stored back in h0
		h0 = h0 & 0x3ffffff;
		// Finally, the value of c (carry from the previous operation) is added to h1
		h1 += c;		 

		//Update the variables m and bytes after each iteration of the while loop in the poly1305_blocks function:
		m += poly1305_block_size;			//Moving the pointer m to the start of the next block of the message that needs to be processed
		bytes -= poly1305_block_size;		//Reducing the count of remaining bytes by the size of the block that was just processed
	}

	//After all blocks have been processed, the final h values are stored back into the context:
    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}


void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes) {
    size_t i;

    //Checks if there are any leftover bytes from the previous update that were not enough to form a complete block
    if (ctx->leftover) {											
        size_t want = (poly1305_block_size - ctx->leftover); 				//Calculating how many bytes are needed to complete a block
        //Ensuring we don't take more byte than available
		if (want > bytes)	
            want = bytes;
		//Filling the buffer with the necessary bytes
        for (i = 0; i < want; i++)
            ctx->buffer[ctx->leftover + i] = m[i];
		//Updating the number of bytes left, the position in the message and the number of bytes in the buffer
        bytes -= want;
        m += want;
        ctx->leftover += want;
		//If the buffer is still not full, the function returns
        if (ctx->leftover < poly1305_block_size)
            return;
		//If a full block has been formed, it's processed and the leftovers are set to 0
        poly1305_blocks(ctx, ctx->buffer, poly1305_block_size);
        ctx->leftover = 0;
    }

    //Checks if there are enough bytes left to form a complete block
    if (bytes >= poly1305_block_size) {
		//We need a number that is the largest multiple of poly1305_block_size that is less than or equal to bytes:
		//Subtracting 1 to the block_size (multiple of 2) and we get a binary like "111" -> this is then inverted with NOT before being placed with AND with "bytes" --> this gets us the largest multiple of poly1305_block_size that is less than or equal to bytes
        size_t want = (bytes & ~(poly1305_block_size - 1));					
        poly1305_blocks(ctx, m, want);
		//Updating the number of bytes left, the position in the message
        m += want;
        bytes -= want;
    }

    //Checks if there are any bytes left, if so they are stored in the buffer
    if (bytes) {
        for (i = 0; i < bytes; i++)
            ctx->buffer[ctx->leftover + i] = m[i];
		//Updating leftovers value
        ctx->leftover += bytes;	
    }
}


void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]) {
	//Var declaration:
	unsigned long h0,h1,h2,h3,h4,c;
	unsigned long g0,g1,g2,g3,g4;
	unsigned long long f;
	unsigned long mask;

	//Checks if there are any leftover bytes from the previous update
	if (ctx->leftover) {
		size_t i = ctx->leftover;	//Setting i to the number of leftovers bytes
		//Padding to fill up the last block
		ctx->buffer[i++] = 1;		
		//Setting all the remaining bytes in the buffer to 0
		for (; i < poly1305_block_size; i++)					
			ctx->buffer[i] = 0;
		//Flag that indicates that this is the last block to be processed
		ctx->final = 1;	
		//Processing the final block										
		poly1305_blocks(ctx, ctx->buffer, poly1305_block_size);
	}

	//Initializing h with the current state:
	h0 = ctx->h[0];
	h1 = ctx->h[1];
	h2 = ctx->h[2];
	h3 = ctx->h[3];
	h4 = ctx->h[4];

	//Perform a right shift operation on h1 to divide it by 2^26 to prevent overflow in the subsequent steps
	c = h1 >> 26; 
	//Perform a bitwise AND operation on h1 to keep only the lowest 26 bits to ensure that h1 is less than 2^26
	h1 = h1 & 0x3ffffff;
	//Add the carry to h2 to propagate the overflow from h1 to h2
	h2 += c; 
	//Repeat the process for h2 and propagate any overflow to h3
	c = h2 >> 26; 
	h2 = h2 & 0x3ffffff;
	//Repeat the process for h3 and propagate any overflow to h4
	h3 += c; 
	c = h3 >> 26; 
	h3 = h3 & 0x3ffffff;
	//Repeat the process for h4 and propagate any overflow to h0
	h4 += c; 
	c = h4 >> 26; 
	h4 = h4 & 0x3ffffff;
	//Add five times the carry to h0. (multiplication by 5 is specific to the Poly1305 algorithm)
	h0 += c * 5; 
	//Repeat the process for h0 and propagate any overflow to h1
	c = h0 >> 26; 
	h0 = h0 & 0x3ffffff;
	//Add the final carry to h1. This completes the carry propagation process, ensuring that all elements of h are less than 2^26
	h1 += c; 


	//Compute h + -p 
	//Adding 5 to h0, storing the result in g0, then dividing g0 by 2^26 and storing the result in c
	g0 = h0 + 5;		c = g0 >> 26;		g0 &= 0x3ffffff;
	//Process repeated for h1, h2, h3, h4
	g1 = h1 + c;		c = g1 >> 26;		g1 &= 0x3ffffff;
	g2 = h2 + c;		c = g2 >> 26;		g2 &= 0x3ffffff;
	g3 = h3 + c;		c = g3 >> 26;		g3 &= 0x3ffffff;
	//Adding c to h4 and then subtracting 2^26 from the result. (in order to keep the final result within a certain range)
	g4 = h4 + c - (1UL << 26);

	//Calculate the mask based on the most significant bit of g4
	mask = (g4 >> ((sizeof(unsigned long) * 8) - 1)) - 1;

	//Apply mask from g0 to g4
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;

	//Invert the mask
	mask = ~mask;

	//Apply the inverted mask to h0 to h4 and combine it with g0 to g4, this selects the values of h0 to h4 if h < p
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	//Reducion operation: h = h % (2^128) 
	//Combining the lower 6 bits of h1 with h0 and then taking the remainder when divided by 2^32. (this is done to ensure that h0 is less than 2^32)
	h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
	//Shifting h1 right by 6 bits, combining it with the lower 12 bits of h2, and then taking the remainder when divided by 2^32. (this is done to ensure that h1 is less than 2^32)
	h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
	//Shifting h2 right by 12 bits, combining it with the lower 18 bits of h3, and then taking the remainder when divided by 2^32. (this is done to ensure that h2 is less than 2^32)
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	//Shifting h3 right by 18 bits, combining it with the lower 24 bits of h4, and then taking the remainder when divided by 2^32. (this is done to ensure that h3 is less than 2^32)
	h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

	//Computing mac = (h + pad) % (2^128) 
	//Adding a padding value to h0 and -> storing the result in f -> casting to an unsigned long -> storing it back in h0. (this is done to ensure that h0 is less than 2^32)
	f = (unsigned long long)h0 + ctx->pad[0]            ;		h0 = (unsigned long)f;
	//Same but with carry from the prev operations
	f = (unsigned long long)h1 + ctx->pad[1] + (f >> 32);		h1 = (unsigned long)f;
	f = (unsigned long long)h2 + ctx->pad[2] + (f >> 32);		h2 = (unsigned long)f;
	f = (unsigned long long)h3 + ctx->pad[3] + (f >> 32);		h3 = (unsigned long)f;

	//Converting to 8bit for convenience
	U32TO8(mac +  0, h0);
	U32TO8(mac +  4, h1);
	U32TO8(mac +  8, h2);
	U32TO8(mac + 12, h3);

	//Resetting the state
	ctx->h[0] = 0;
	ctx->h[1] = 0;
	ctx->h[2] = 0;
	ctx->h[3] = 0;
	ctx->h[4] = 0;
	ctx->r[0] = 0;
	ctx->r[1] = 0;
	ctx->r[2] = 0;
	ctx->r[3] = 0;
	ctx->r[4] = 0;
	ctx->pad[0] = 0;
	ctx->pad[1] = 0;
	ctx->pad[2] = 0;
	ctx->pad[3] = 0;
}

void poly1305_auth(unsigned char mac[16], const unsigned char *m, size_t bytes, const unsigned char key[32]) {
	poly1305_context ctx;
	poly1305_init(&ctx, key);
	poly1305_update(&ctx, m, bytes);
	poly1305_finish(&ctx, mac);
}

