#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pmsis.h"
#include "pmsis/cluster/dma/cl_dma.h"

#include "chacha20.h"
#include "poly1305.h"

#define C20_BLOCKLEN 64
#define BUFF_SIZE (3*NUM_CORES*C20_BLOCKLEN)

#ifdef MEM_SIZE
    #if MEM_SIZE==512
        #include "testvectorC20P13050K.txt"
    #elif MEM_SIZE==1
        #include "testvectorC20P13051K.txt"
    #elif MEM_SIZE==2
        #include "testvectorC20P13052K.txt"
    #elif MEM_SIZE==4
        #include "testvectorC20P13054K.txt"
    #elif MEM_SIZE==8
        #include "testvectorC20P13058K.txt"
    #elif MEM_SIZE==16
        #include "testvectorC20P130516K.txt"
    #elif MEM_SIZE==32
        #include "testvectorC20P130532K.txt"
    #endif
#endif

PI_L1 uint32_t key[8] = {
    0x80818283, 0x84858687, 0x88898a8b, 0x8c8d8e8f,
    0x90919293, 0x94959697, 0x98999a9b, 0x9c9d9e9f
};

PI_L1 uint32_t nonce[3] = { 0x07000000, 0x40414243, 0x44454647 };

PI_L1 uint8_t mac[16];

PI_L1 uint8_t aad[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

// Computation variables
PI_L1 uint32_t counter = 1;
PI_L1 int len;
PI_L1 int size;
PI_L1 int plain_size;

PI_L1 int counter_mac = 0;
PI_L1 poly1305_context ctx;

// External buffer, output of the DMA after the encryption
PI_L2 uint8_t* ext_buff;

PI_L2 uint8_t* in_buff;

// 3*NUM_CORES*64 bytes buffer in the L1 memory, required for the DMA transfer in parallel to the computation
PI_L1 uint8_t buffer[BUFF_SIZE];

// Control variables, pointing to each section of the L1 buffer
PI_L1 uint8_t bit = 0; // points to the section to be encrypted
PI_L1 uint8_t ext2locbit = 0; // points to the section to be sent into L1
PI_L1 uint8_t loc2extbit = 0; // points to the section to be sent into L2

// Index of the loop iteration (every cycle NUM_CORES C20-blocks are encrypted)
PI_L1 int indice=0;

#if defined(CLUSTER)
void pe_entry(void *arg)
{
    // Get the core ID of the current core
	int id = pi_core_id();

    // Encrypt the buffer portion assigned to this core
    chacha20_encrypt(&buffer[id*C20_BLOCKLEN+bit*BUFF_SIZE/3], &buffer[id*C20_BLOCKLEN+bit*BUFF_SIZE/3], key, nonce, counter+id);
    
    pi_cl_team_barrier();
    return;
}

void cluster_entry(void *arg)
{   
    // Defining length
    len = sizeof(plaintext);
    plain_size = len + (64 - (len % 64)) % 64; // value required for poly update
    // Padding to the next multiple of NUM_CORES*64 
    int remainder = len % (NUM_CORES * C20_BLOCKLEN);
    size = (remainder != 0) ? len + NUM_CORES * C20_BLOCKLEN - remainder : len;
    
    // Calculate the length and size of the Additional Authenticated Data (AAD)
    size_t aad_len = sizeof(aad);
    size_t aad_size = aad_len + (16 - (aad_len % 16)) % 16;

    // Allocate memory for padded AAD and initialize it
    uint8_t* aad_padded = pi_l2_malloc(aad_size);
    memcpy(aad_padded, aad, aad_len);
    memset(&aad_padded[aad_len], 0, aad_size-aad_len);

    //Buffer for the plaintext
    in_buff = pi_l2_malloc((size_t) size);
    //Buffer for the ciphertext
    ext_buff = pi_l2_malloc((size_t) size + 16); //Allocate output memory multiple of 64 + extra space for MAC
    
    //Copy the input in the input buffer
    memcpy(in_buff, plaintext, (size_t) len); 
    memset(&in_buff[len], 0, (size_t) (size-len)); //Padding the input

    uint8_t poly_key[64];

    // Get the poly key
    chacha20_block((uint32_t *)poly_key, key, 0, nonce);

    // Get the concatenation of the plaintext and aad lenghts for authentication final operations
    uint8_t concatenated_lenghts[16] = {
        aad_len & 0xFF,
        (aad_len >> 8) & 0xFF,
        (aad_len >> 16) & 0xFF,
        (aad_len >> 24) & 0xFF,
        0, 0, 0, 0,
        len & 0xFF,
        (len >> 8) & 0xFF,
        (len >> 16) & 0xFF,
        (len >> 24) & 0xFF,
        0, 0, 0, 0
    };

    // Perform Poly preliminary operations
    poly1305_init(&ctx, poly_key);
    poly1305_update(&ctx, aad_padded, aad_size);

    pi_cl_dma_cmd_t copy[2];

    // Buffer initialization, wait for the first chunk to be transported into L1
    pi_cl_dma_cmd((int)in_buff, (int)buffer, BUFF_SIZE/3, PI_CL_DMA_DIR_EXT2LOC, &copy[0]);
    pi_cl_dma_cmd((int)&in_buff[BUFF_SIZE/3], (int)&buffer[BUFF_SIZE/3], BUFF_SIZE/3, PI_CL_DMA_DIR_EXT2LOC, &copy[1]);
    pi_cl_dma_cmd_wait(&copy[0]);

    // Fork the team of cores to process the first block
    pi_cl_team_fork((NUM_CORES), pe_entry, 0);

    for(uint8_t t=0; t<NUM_CORES && counter_mac<plain_size; ++t, counter_mac+=C20_BLOCKLEN){
        // Handle partial blocks by padding with zeros
        if(counter_mac + C20_BLOCKLEN > len)
            memset(&buffer[t*C20_BLOCKLEN+bit*BUFF_SIZE/3 + len - counter_mac], 0, C20_BLOCKLEN - len + counter_mac);
        // Update the tag with the current block
        poly1305_update(&ctx, &buffer[t*C20_BLOCKLEN+bit*BUFF_SIZE/3], C20_BLOCKLEN);
    }

    // Control logic update for the next iteration
    bit = (indice+1) % 3;
    ext2locbit = (indice+2) % 3;
    loc2extbit = (indice) % 3;

    // Update counter for the next iteration
    counter = (counter == 255) ? 0 : counter + NUM_CORES;

    pi_cl_dma_cmd_wait(&copy[1]);

    // Central encryption loop
    for(indice=1; indice<(int) (size/(NUM_CORES*C20_BLOCKLEN)); indice++){

        pi_cl_dma_cmd((int)&ext_buff[(indice-1)*BUFF_SIZE/3], (int)&buffer[loc2extbit*BUFF_SIZE/3], NUM_CORES*C20_BLOCKLEN, PI_CL_DMA_DIR_LOC2EXT, &copy[0]);
        pi_cl_dma_cmd((int)&in_buff[(indice-1)*BUFF_SIZE/3+2*BUFF_SIZE/3], (int)&buffer[ext2locbit*BUFF_SIZE/3], BUFF_SIZE/3, PI_CL_DMA_DIR_EXT2LOC, &copy[1]);
        
        pi_cl_team_fork((NUM_CORES), pe_entry, 0);

        for(uint8_t t=0; t<NUM_CORES && counter_mac<plain_size; ++t, counter_mac+=C20_BLOCKLEN){
            if(counter_mac + C20_BLOCKLEN > len)
                memset(&buffer[t*C20_BLOCKLEN+bit*BUFF_SIZE/3 + len - counter_mac], 0, C20_BLOCKLEN - len + counter_mac);
            poly1305_update(&ctx, &buffer[t*C20_BLOCKLEN+bit*BUFF_SIZE/3], C20_BLOCKLEN);
        }

        // Control logic update for the next iteration
        bit = (indice+1) % 3;
        ext2locbit = (indice+2) % 3;
        loc2extbit = (indice) % 3;

        // Update counter for the next iteration
        counter = (counter == 255) ? 0 : counter + NUM_CORES;

        pi_cl_dma_cmd_wait(&copy[0]);
        pi_cl_dma_cmd_wait(&copy[1]);

    }

    // Final encryption itearation: both encrypted buffers to be sent back to L2
    pi_cl_dma_cmd((int)&ext_buff[(indice-1)*BUFF_SIZE/3], (int)&buffer[loc2extbit*BUFF_SIZE/3], NUM_CORES*C20_BLOCKLEN, PI_CL_DMA_DIR_LOC2EXT, &copy[0]);  

    pi_cl_team_fork((NUM_CORES), pe_entry, 0);

    pi_cl_dma_cmd((int)&ext_buff[indice*BUFF_SIZE/3], (int)&buffer[bit*BUFF_SIZE/3], NUM_CORES*C20_BLOCKLEN, PI_CL_DMA_DIR_LOC2EXT, &copy[1]);

    for(uint8_t t=0; t<NUM_CORES && counter_mac<plain_size; ++t, counter_mac+=C20_BLOCKLEN){
        if(counter_mac + C20_BLOCKLEN > len)
            memset(&buffer[t*C20_BLOCKLEN+bit*BUFF_SIZE/3 + len - counter_mac], 0, C20_BLOCKLEN - len + counter_mac);
        poly1305_update(&ctx, &buffer[t*C20_BLOCKLEN+bit*BUFF_SIZE/3], C20_BLOCKLEN);
    }

    pi_cl_dma_cmd_wait(&copy[0]);
    pi_cl_dma_cmd_wait(&copy[1]);

    // Final poly operations
    poly1305_update(&ctx, concatenated_lenghts, 16);
    poly1305_finish(&ctx, mac);

    memcpy(ext_buff + len, mac, 16);

    /*VERIFING*/
    #ifdef DEBUG
    if (memcmp(ext_buff, ciphertext, (size_t) len+16) == 0)
        printf("Ciphertext and Digest verified successfully.\n");
    else {
        printf("Ciphertext and Digest not verified\n");            
        printf("Ciphertext: ");
        for (int k = 0; k < 16; ++k)
            printf("%02x ", ext_buff[k+len]);
        printf("\n");
    }
    #endif
}
#endif


static int test_entry(){
#if defined(CLUSTER)
    struct pi_device cluster_dev;
    struct pi_cluster_conf cl_conf;
    struct pi_cluster_task cl_task;

    pi_cluster_conf_init(&cl_conf);
    pi_open_from_conf(&cluster_dev, &cl_conf);
    if (pi_cluster_open(&cluster_dev))
    {
        return -1;
    }

    pi_cluster_send_task_to_cl(&cluster_dev, pi_cluster_task(&cl_task, cluster_entry, NULL));

    pi_cluster_close(&cluster_dev);
#endif
#if !defined(CLUSTER)
    printf("Hello from FC\n");
#endif

    return 0;
}

static void test_kickoff(void *arg){
    int ret = test_entry();
    pmsis_exit(ret);
}

int main(){
    return pmsis_kickoff((void *)test_kickoff);
}