/*

This is an implementation of the AES algorithm GCM mode.

NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.

*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "aes.h"

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#define Nk 8
#define Nr 14

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/

static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/

#define getSBoxValue(num) (sbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }

    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }

    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}


/**********************************************************************************************/
/*                                  AES ALGORITHM                                             */
/**********************************************************************************************/

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset. [Offset = Row number]. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

/**********************************************************************************************/
/*                                Moltiplication in GF(2^128)                                 */
/**********************************************************************************************/

// Define the irreducible polynomial R for GF(2^128)
#define R 0xE1 // R = 11100001

// Function to perform right shift on a 128-bit number represented as a 16-byte array
// Each byte is shifted to the right, with the least significant bit of each byte 
// becoming the most significant bit of the next byte.
void right_shift(uint8_t V[16]) {
    for (int i = 15; i > 0; i--) {
        // Shift current byte and add carry from previous byte
        V[i] = (V[i] >> 1) | ((V[i - 1] & 0x01) << 7);
    }
    // Shift the most significant byte
    V[0] >>= 1;
}

// Function to perform multiplication in GF(2^128)
// X, Y, and Z are 128-bit numbers represented as 16-byte arrays
// This function computes Z = X * Y in GF(2^128)
void gf128_mul(uint8_t X[16], uint8_t Y[16], uint8_t Z[16]) {
    uint8_t V[16];
    
    // Copy the 128-bit number X into V
    for (int i = 0; i < 16; i++) {
        V[i] = X[i];
    }

    // Initialize Z to 0 (128-bit zero)
    for (int i = 0; i < 16; i++) {
        Z[i] = 0;
    }

    // Iterate over each bit of the 128-bit number Y
    for (int i = 0; i < 128; i++) {
        // If the current bit of Y (Y[i]) is 1, perform Z = Z ^ V
        if (Y[i / 8] & (1 << (7 - i % 8))) {
            for (int j = 0; j < 16; j++) {
                Z[j] ^= V[j];
            }
        }
        
        // Check the least significant bit of the most significant byte of V
        if (V[15] & 0x01) {
            // If V127 = 1, perform right shift on V and then XOR with the polynomial R
            right_shift(V);
            V[0] ^= R;
        } else {
            // If V127 = 0, just perform right shift on V
            right_shift(V);
        }
    }
}



/*****************************************************************************/
/*                          Public functions:                                */
/*****************************************************************************/


/* Symmetrical operation: same function for encrypting and decrypting.
 * Note: any IV/nonce should never be reused with the same key.
 * This function processes a buffer of data, encrypting or decrypting it
 * using the given context which contains the key and IV.
 */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
    uint8_t buffer[AES_BLOCKLEN]; // Buffer for storing the encrypted IV
    size_t i; // Index for the input buffer
    int j = 0; // Counter for the number of blocks processed
    int bi; // Index for the buffer

    for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
    {
        // If we've processed a whole block, we need to regenerate the XOR complement in buffer
        if (bi == AES_BLOCKLEN)
        {
            // Copy IV to buffer and encrypt it
            memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
            Cipher((state_t*)buffer, ctx->RoundKey);
            j++;

            // Increment IV and handle overflow
            for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
            {
                // If byte overflows, reset to 0 and continue to the next byte
                if (ctx->Iv[bi] == 255)
                {
                    ctx->Iv[bi] = 0;
                    continue;
                }
                // Increment the current byte and break the loop
                ctx->Iv[bi] += 1;
                break;
            }
            bi = 0; // Reset buffer index
        }

        // XOR the input buffer with the encrypted IV (buffer) to get the ciphertext/plaintext
        buf[i] ^= buffer[bi];
    }
}

// Encrypts a single block using the current IV and round keys
// Counter incrementation is done in the main encryption/decryption function
void AES_CTR_xcrypt(struct AES_ctx* ctx, uint8_t* buf0)
{
    // Encrypt the IV
    Cipher((state_t*)ctx->Iv, ctx->RoundKey);

    // XOR the encrypted IV with the input buffer (buf0) to produce the output
    for (uint8_t i = 0; i < AES_BLOCKLEN; ++i)
    {
        buf0[i] ^= ctx->Iv[i];
    }
}

// Cipher is the main function that encrypts the PlainText.
// This function performs the core AES encryption on a single block (state) using the provided round keys.
void Cipher(state_t* state, const uint8_t* RoundKey)
{
    uint8_t round = 0;

    // Add the first round key to the state before starting the rounds.
    AddRoundKey(0, state, RoundKey);

    // Perform Nr rounds of encryption. The first Nr-1 rounds are identical, 
    // while the last round omits the MixColumns step.
    for (round = 1; ; ++round)
    {
        SubBytes(state); // Substitute bytes using the S-box
        ShiftRows(state); // Shift the rows of the state
        if (round == Nr) {
            break; // Exit the loop before the last round
        }
        MixColumns(state); // Mix the columns of the state
        AddRoundKey(round, state, RoundKey); // Add the round key
    }
    // Add the final round key to complete the encryption
    AddRoundKey(Nr, state, RoundKey);
}

/**********************************************************************************************/
/*                                    TAG generation                                          */
/**********************************************************************************************/

// Function to initialize the tag by performing multiplication of the first AAD block with the hash key
void init_tag(uint8_t* text, uint8_t* tag, uint8_t* h) {
    // First iteration: multiply the first AAD block (text) with the hash key (h) and store in tag
    gf128_mul(text, h, tag);
}


// The update function allows better parallelization and can be concatenated with multiple sections of the ciphertext
// It performs a chain of XOR between the ciphertext and the previous tag
void update_tag(const uint8_t* text, size_t len, uint8_t* tag, uint8_t* h) {
    // Central iterations: XOR between the buffer (tag) and the next block of the ciphertext (text) followed by multiplication with the hash key
    for (uint32_t i = 0; i < len / AES_BLOCKLEN; ++i) {
        for (uint8_t j = 0; j < AES_BLOCKLEN; ++j) {
            tag[j] ^= text[i * AES_BLOCKLEN + j];
        }
        gf128_mul(tag, h, tag);
    }
    return;
}

// Final steps with length and keystream0
void finish_tag(size_t aad_len, size_t len, uint8_t* tag, uint8_t* h, uint8_t* keystream) {
    uint8_t lengths[16];

    // Convert aad_len and len to bits
    aad_len *= 8; // Convert to bits
    len *= 8; // Convert to bits
    for (int i = 0; i < 8; ++i) {
        lengths[15 - i] = len & 0xFF; // Store len in the first 8 bytes (big-endian)
        len >>= 8;
        lengths[7 - i] = aad_len & 0xFF; // Store aad_len in the next 8 bytes (big-endian)
        aad_len >>= 8;
    }

    // XOR tag with the lengths array
    for (int i = 0; i < 16; i++) {
        tag[i] ^= lengths[i];
    }

    // Multiply the tag with the hash key
    gf128_mul(tag, h, tag);

    // XOR the tag with the first keystream block (output of the AES encryption of the first counter value)
    for (uint8_t i = 0; i < AES_BLOCKLEN; ++i) {
        tag[i] ^= keystream[i];
    }

    return;
}


