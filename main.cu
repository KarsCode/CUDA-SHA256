#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda.h>
#include "sha256.cuh"

#define MAX_STRING_SIZE 50

// CUDA Kernel for sha256 computation on multiple strings
__global__ void sha256_cuda(BYTE *data, size_t *data_sizes, int num_strings, BYTE *digests) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (i < num_strings) {
        size_t size = data_sizes[i];
        BYTE *str_data = &data[i * MAX_STRING_SIZE];  // Offset for each string
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, str_data, size);
        sha256_final(&ctx, &digests[i * 32]); // Each hash is 32 bytes
    }
}

// Convert a string to byte array (Helper function)
BYTE *get_string_data(const char *str, size_t *size) {
    *size = strlen(str);
    BYTE *buffer;
    cudaMallocManaged(&buffer, (*size + 1) * sizeof(char)); // Allocate memory for the string
    memcpy(buffer, str, *size);  // Copy string into buffer
    buffer[*size] = '\0';  // Null-terminate the string
    return buffer;
}

// Main function for SHA256 computation on multiple strings
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <string1> <string2> ... <stringN>\n", argv[0]);
        return 1;
    }

    int num_strings = argc - 1;
    size_t *input_sizes;
    BYTE *input_data, *digests;

    // Allocate memory for input sizes
    cudaMallocManaged(&input_sizes, num_strings * sizeof(size_t));

    // Allocate memory for all input data
    cudaMallocManaged(&input_data, num_strings * MAX_STRING_SIZE * sizeof(BYTE));

    // Fill the data for each string
    for (int i = 0; i < num_strings; i++) {
        size_t size;
        BYTE *data = get_string_data(argv[i + 1], &size);
        memcpy(&input_data[i * MAX_STRING_SIZE], data, size);  // Copy the string data into the buffer
        input_sizes[i] = size;  // Store the size of the string
        cudaFree(data);  // Free the temporary data buffer
    }

    // Allocate memory for storing the digests
    cudaMallocManaged(&digests, num_strings * 32 * sizeof(BYTE));  // Each SHA256 hash is 32 bytes

    // CUDA event variables for timing
    cudaEvent_t start, stop;
    float elapsedTime;

    // Create CUDA events for timing
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    // Record the start time
    cudaEventRecord(start);

    // Launch CUDA kernel to compute the hashes
    int blockSize = 256;  // Number of threads per block
    int numBlocks = (num_strings + blockSize - 1) / blockSize;  // Calculate number of blocks needed

    sha256_cuda<<<numBlocks, blockSize>>>(input_data, input_sizes, num_strings, digests);

    // Wait for kernel to finish
    cudaDeviceSynchronize();

    // Record the end time
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);

    // Calculate elapsed time
    cudaEventElapsedTime(&elapsedTime, start, stop);

    // Print the computed SHA256 hashes
    for (int i = 0; i < num_strings; i++) {
        printf("Hash of string %s: ", argv[i + 1]);
        for (int j = 0; j < 32; j++) {
            printf("%02x", digests[i * 32 + j]);
        }
        printf("\n");
    }

    // Print the total time taken
    printf("Total time taken for computation: %.4f ms\n", elapsedTime);

    // Clean up
    cudaFree(input_data);
    cudaFree(input_sizes);
    cudaFree(digests);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    cudaDeviceReset();
    return 0;
}
