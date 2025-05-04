#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"
#include "pmsis.h"
#include "pmsis/cluster/dma/cl_dma.h"

#ifdef MEM_SIZE
    #if MEM_SIZE==512
        #include "testvectorAES256GCM0K.txt"
    #elif MEM_SIZE==1
        #include "testvectorAES256GCM1K.txt"
    #elif MEM_SIZE==2
        #include "testvectorAES256GCM2K.txt"
    #elif MEM_SIZE==4
        #include "testvectorAES256GCM4K.txt"
    #elif MEM_SIZE==8
        #include "testvectorAES256GCM8K.txt"
    #elif MEM_SIZE==16
        #include "testvectorAES256GCM16K.txt"
    #elif MEM_SIZE==32
        #include "testvectorAES256GCM32K.txt"
    #endif
#endif

#define BUFF_SIZE (3*NUM_CORES*AES_BLOCKLEN)

PI_L1 uint8_t key[AES_KEYLEN] = {
    0xE3, 0xC0, 0x8A, 0x8F, 0x06, 0xC6, 0xE3, 0xAD,
    0x95, 0xA7, 0x05, 0x57, 0xB2, 0x3F, 0x75, 0x48,
    0x3C, 0xE3, 0x30, 0x21, 0xA9, 0xC7, 0x2B, 0x70,
    0x25, 0x66, 0x62, 0x04, 0xC6, 0x9C, 0x0B, 0x72
};

PI_L1 uint8_t iv[AES_BLOCKLEN] = {
    0x12, 0x15, 0x35, 0x24, 0xC0, 0x89, 0x5E, 0x81,
    0xB2, 0xC2, 0x84, 0x65, 0x00, 0x00, 0x00, 0x02
};

// External buffer, output of the DMA after the encryption
PI_L2 uint8_t* ext_buff;

PI_L2 uint8_t* in_buff;

// 3*NUM_CORES*16 bytes buffer in the L1 memory, required for the DMA transfer in parallel to the computation
PI_L1 uint8_t buffer[BUFF_SIZE];

// Control variables, pointing to each section of the L1 buffer
PI_L1 uint8_t bit = 0; // points to the section to be encrypted
PI_L1 uint8_t ext2locbit = 0; // points to the section to be sent into L1
PI_L1 uint8_t loc2extbit = 0; // points to the section to be sent into L2

// Index of the loop iteration (every cycle NUM_CORES AES-blocks are encrypted)
PI_L1 int indice=0;

PI_L1 int size;

void pe_entry(void *arg)
{

    struct AES_ctx ctx;

    // Get the core ID of the current core
	int id = pi_core_id();

    // define local counter and initialize it with the IV
    uint8_t counter[AES_BLOCKLEN];
    memcpy(counter, iv, AES_BLOCKLEN);

    // Increment the local counter based on the core ID
    for(uint8_t increment=0; increment<id; increment++){
        for (uint8_t bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
        {
            // Handle overflow
            if (counter[bi] == 255)
            {
                counter[bi] = 0;
                continue;
            }
            counter[bi] += 1;
            break;
        }
    }
    pi_cl_team_barrier();

    // Initialize AES context with the key and the incremented counter
    AES_init_ctx_iv(&ctx, key, counter);
    
    // Encrypt the buffer portion assigned to this core
    AES_CTR_xcrypt(&ctx, &buffer[id*AES_BLOCKLEN+bit*BUFF_SIZE/3]);
    
    pi_cl_team_barrier();

    return;
}

void cluster_entry(void *arg)
{

    // Calculate the length of the plaintext and the padded sizes
    int len = sizeof(plaintext);
    size = len + (NUM_CORES * AES_BLOCKLEN - (len % (NUM_CORES * AES_BLOCKLEN))) % (NUM_CORES * AES_BLOCKLEN);

    // Allocate memory for input and output buffers
    ext_buff = pi_l2_malloc((size_t) size); // multiple of NUM_CORES*AES_BLOCKLEN
    in_buff = pi_l2_malloc((size_t) size);
    memcpy(in_buff, plaintext, (size_t) len); // Copy the input in the input buffer
    memset(&in_buff[len], 0, (size_t) (size-len)); // Pad the input

    pi_cl_dma_cmd_t copy[2];

    // Initialize buffers, wait for the first chunk to be transferred to L1 memory
    pi_cl_dma_cmd((int)in_buff, (int)buffer, BUFF_SIZE/3, PI_CL_DMA_DIR_EXT2LOC, &copy[0]);
    pi_cl_dma_cmd((int)&in_buff[BUFF_SIZE/3], (int)&buffer[BUFF_SIZE/3], BUFF_SIZE/3, PI_CL_DMA_DIR_EXT2LOC, &copy[1]);
    pi_cl_dma_cmd_wait(&copy[0]);

    // Fork the team of cores to process the first block
    pi_cl_team_fork((NUM_CORES), pe_entry, 0);

    // Update control logic for the next iteration
    bit = (indice+1) % 3;
    ext2locbit = (indice+2) % 3;
    loc2extbit = (indice) % 3;

    // Update Iv for the next iteration
    for(uint8_t increment=0; increment<NUM_CORES; increment++){
        for (uint8_t bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
        {
            if (iv[bi] == 255)
            {
                iv[bi] = 0;
                continue;
            }
            iv[bi] += 1;
            break;
        }
    }

    pi_cl_dma_cmd_wait(&copy[1]);

    // Central encryption loop
    for(indice=1; indice<(int) (size/(NUM_CORES*AES_BLOCKLEN)); indice++){

        pi_cl_dma_cmd((int)&ext_buff[(indice-1)*BUFF_SIZE/3], (int)&buffer[loc2extbit*BUFF_SIZE/3], NUM_CORES*AES_BLOCKLEN, PI_CL_DMA_DIR_LOC2EXT, &copy[0]);
        pi_cl_dma_cmd((int)&in_buff[(indice-1)*BUFF_SIZE/3+2*BUFF_SIZE/3], (int)&buffer[ext2locbit*BUFF_SIZE/3], BUFF_SIZE/3, PI_CL_DMA_DIR_EXT2LOC, &copy[1]);
        
        pi_cl_team_fork((NUM_CORES), pe_entry, 0);

        // Update control logic for the next iteration
        bit = (indice+1) % 3;
        ext2locbit = (indice+2) % 3;
        loc2extbit = (indice) % 3;

        // Update Iv for the next iteration
        for(uint8_t increment=0; increment<NUM_CORES; increment++){
            for (uint8_t bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
            {
                if (iv[bi] == 255)
                {
                    iv[bi] = 0;
                    continue;
                }
                iv[bi] += 1;
                break;
            }
        }
        pi_cl_dma_cmd_wait(&copy[0]);
        pi_cl_dma_cmd_wait(&copy[1]);

    }

    // Final encryption iteration: both encrypted buffers to be sent back to L2
    pi_cl_dma_cmd((int)&ext_buff[(indice-1)*BUFF_SIZE/3], (int)&buffer[loc2extbit*BUFF_SIZE/3], NUM_CORES*AES_BLOCKLEN, PI_CL_DMA_DIR_LOC2EXT, &copy[0]);  

    pi_cl_team_fork((NUM_CORES), pe_entry, 0);

    pi_cl_dma_cmd((int)&ext_buff[indice*BUFF_SIZE/3], (int)&buffer[bit*BUFF_SIZE/3], NUM_CORES*AES_BLOCKLEN, PI_CL_DMA_DIR_LOC2EXT, &copy[1]);
    pi_cl_dma_cmd_wait(&copy[0]);
    pi_cl_dma_cmd_wait(&copy[1]);

    #ifdef DEBUG
    if(memcmp(ext_buff, ciphertext, len)==0)
        printf("Test success\n");
    else
        printf("Test failed\n");
    #endif

    // Free allocated memory
    pi_l2_free(ext_buff, (size_t) size);
    pi_l2_free(in_buff, (size_t) size);

    return;
}

static int test_entry()
{
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

    return 0;
}

static void test_kickoff(void *arg)
{
    int ret = test_entry();
    pmsis_exit(ret);
}

int main()
{
    return pmsis_kickoff((void *)test_kickoff);
}
