#include <stdio.h>
#include <stdlib.h>
#include <cuda.h>
#include <string.h>
#include <ctype.h>
#include "sha256.cuh"

#define MAX_HASHES 10   // Maximum number of hashes to process
#define HASH_SIZE 32    // SHA-256 hash size in bytes
#define MAX_WORD_LENGTH 8  // Max length of brute-force words
#define ALPHABET_SIZE 26  // 'a' to 'z'

// Convert a hex string (64 chars) to a byte array (32 bytes)
void hex_to_bytes(const char *hex, BYTE *bytes) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// Generate a word from an index (variable length)
__device__ void generate_word(int index, int length, char *word) {
    for (int i = 0; i < length; i++) {
        word[i] = 'a' + (index / (int)powf(ALPHABET_SIZE, i)) % ALPHABET_SIZE;
    }
    word[length] = '\0';
}

// CUDA kernel for brute-forcing multiple SHA-256 hashes
__global__ void sha256_bruteforce(BYTE *target_hashes, int num_hashes, char *results, int *found_flags, int length) {
    int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= pow(ALPHABET_SIZE, length)) return;

    char candidate[MAX_WORD_LENGTH + 1];
    generate_word(index, length, candidate);

    BYTE digest[HASH_SIZE];
    SHA256_CTX ctx;
    
    // Compute SHA-256 for the candidate word
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE*)candidate, length);
    sha256_final(&ctx, digest);

    // Compare against all target hashes
    for (int h = 0; h < num_hashes; h++) {
        bool match = true;
        for (int i = 0; i < HASH_SIZE; i++) {
            if (digest[i] != target_hashes[h * HASH_SIZE + i]) {
                match = false;
                break;
            }
        }
        if (match) {
            for (int i = 0; i < length + 1; i++) {
                results[h * (MAX_WORD_LENGTH + 1) + i] = candidate[i];
            }
            found_flags[h] = 1;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <SHA256-hash1> [<SHA256-hash2> ...]\n", argv[0]);
        return 1;
    }

    int num_hashes = argc - 1;
    if (num_hashes > MAX_HASHES) {
        printf("Too many hashes! Max allowed is %d.\n", MAX_HASHES);
        return 1;
    }

    // Convert input hashes to byte arrays
    BYTE target_hashes[MAX_HASHES * HASH_SIZE];
    for (int i = 0; i < num_hashes; i++) {
        hex_to_bytes(argv[i + 1], &target_hashes[i * HASH_SIZE]);
    }

    // Allocate device memory
    BYTE *d_target_hashes;
    char *d_results;
    int *d_found_flags, h_found_flags[MAX_HASHES] = {0};
    char h_results[MAX_HASHES][MAX_WORD_LENGTH + 1] = {{0}};

    cudaMalloc((void**)&d_target_hashes, num_hashes * HASH_SIZE);
    cudaMalloc((void**)&d_results, num_hashes * (MAX_WORD_LENGTH + 1));
    cudaMalloc((void**)&d_found_flags, num_hashes * sizeof(int));

    // Copy data to GPU
    cudaMemcpy(d_target_hashes, target_hashes, num_hashes * HASH_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(d_found_flags, h_found_flags, num_hashes * sizeof(int), cudaMemcpyHostToDevice);

    // Brute-force increasing word lengths
    int blockSize = 256;
    for (int length = 1; length <= MAX_WORD_LENGTH; length++) {
        int numWords = pow(ALPHABET_SIZE, length);
        int numBlocks = (numWords + blockSize - 1) / blockSize;
        
        printf("Trying %d-letter words...\n", length);
        sha256_bruteforce<<<numBlocks, blockSize>>>(d_target_hashes, num_hashes, d_results, d_found_flags, length);
        cudaDeviceSynchronize();

        // Copy results back to host
        cudaMemcpy(h_results, d_results, num_hashes * (MAX_WORD_LENGTH + 1), cudaMemcpyDeviceToHost);
        cudaMemcpy(h_found_flags, d_found_flags, num_hashes * sizeof(int), cudaMemcpyDeviceToHost);

        // Check if all hashes are found
        bool allFound = true;
        for (int i = 0; i < num_hashes; i++) {
            if (h_found_flags[i] == 0) {
                allFound = false;
                break;
            }
        }
        if (allFound) break; // Stop if all hashes are cracked
    }

    // Print results
    for (int i = 0; i < num_hashes; i++) {
        if (h_found_flags[i]) {
            printf("Hash %s -> Found: %s\n", argv[i + 1], h_results[i]);
        } else {
            printf("Hash %s -> No match found.\n", argv[i + 1]);
        }
    }

    // Cleanup
    cudaFree(d_target_hashes);
    cudaFree(d_results);
    cudaFree(d_found_flags);
    return 0;
}

