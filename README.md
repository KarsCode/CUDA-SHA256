# **Overview**
This program attempts to **brute-force SHA-256 hashes** by generating possible words and checking if their **SHA-256 hash matches** a given hash. The computation is **accelerated using CUDA**, allowing multiple words to be hashed simultaneously on a **GPU**.

## **How It Works**
1. The user **inputs SHA-256 hashes** that need to be cracked.
2. The program **iterates through possible words** (starting from 1-letter words up to `MAX_WORD_LENGTH`).
3. Each **CUDA thread** generates a candidate word, **hashes it**, and **compares it** with the target hashes.
4. If a match is found, the result is stored and the program stops when all hashes are found.

---

# **Breakdown of the Code**
## **1. Constants and Headers**
```cpp
#include <stdio.h>
#include <stdlib.h>
#include <cuda.h>
#include <string.h>
#include <ctype.h>
#include "sha256.cuh"
```
- **`sha256.cuh`**: A CUDA-compatible SHA-256 implementation.
- **Constants Defined:**
  ```cpp
  #define MAX_HASHES 10      // Maximum hashes to process
  #define HASH_SIZE 32       // SHA-256 hash size (32 bytes)
  #define MAX_WORD_LENGTH 8  // Maximum length of brute-force words
  #define ALPHABET_SIZE 26   // Alphabet size (only 'a' to 'z')
  ```

---

## **2. Converting Hexadecimal Hash Strings to Bytes**
```cpp
void hex_to_bytes(const char *hex, BYTE *bytes) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}
```
- Converts **64-character** SHA-256 hashes (hex string) into a **32-byte array**.
- **Example Input:** `"5d41402abc4b2a76b9719d911017c592"`
- **Example Output:** `{0x5d, 0x41, 0x40, 0x2a, ...}`

---

## **3. Generating Candidate Words in CUDA**
```cpp
__device__ void generate_word(int index, int length, char *word) {
    for (int i = 0; i < length; i++) {
        word[i] = 'a' + (index / (int)powf(ALPHABET_SIZE, i)) % ALPHABET_SIZE;
    }
    word[length] = '\0';
}
```
- Generates a **word from an integer index**.
- Uses **modulus division** to map the index to letters (`'a' to 'z'`).
- Example:  
  - `index = 27` (in a **2-letter word**) → `"ba"`
  - `index = 703` (in a **3-letter word**) → `"aaa"`

---

## **4. CUDA Kernel for Brute-Force Attack**
```cpp
__global__ void sha256_bruteforce(BYTE *target_hashes, int num_hashes, char *results, int *found_flags, int length) {
    int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= pow(ALPHABET_SIZE, length)) return;
```
- Each **CUDA thread** gets a unique `index`, which represents a **candidate word**.
- If `index` exceeds the total number of words for `length`, the thread exits.

### **Hashing the Word**
```cpp
    char candidate[MAX_WORD_LENGTH + 1];
    generate_word(index, length, candidate);

    BYTE digest[HASH_SIZE];
    SHA256_CTX ctx;
    
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE*)candidate, length);
    sha256_final(&ctx, digest);
```
- Converts the index into a **word**.
- Computes its **SHA-256 hash**.

### **Checking Against Target Hashes**
```cpp
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
```
- Compares the computed hash with **each target hash**.
- If a **match is found**, it **stores the word** in `results` and marks `found_flags[h] = 1`.

---

## **5. Main Function**
```cpp
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <SHA256-hash1> [<SHA256-hash2> ...]\n", argv[0]);
        return 1;
    }
```
- Reads **SHA-256 hashes** from command-line arguments.

### **Converting Input Hashes**
```cpp
    BYTE target_hashes[MAX_HASHES * HASH_SIZE];
    for (int i = 0; i < num_hashes; i++) {
        hex_to_bytes(argv[i + 1], &target_hashes[i * HASH_SIZE]);
    }
```
- Converts each input hash from a **hex string to bytes**.

---

## **6. Allocating CUDA Memory**
```cpp
    cudaMalloc((void**)&d_target_hashes, num_hashes * HASH_SIZE);
    cudaMalloc((void**)&d_results, num_hashes * (MAX_WORD_LENGTH + 1));
    cudaMalloc((void**)&d_found_flags, num_hashes * sizeof(int));
```
- Allocates **device memory** for:
  - `d_target_hashes` → Holds input hashes.
  - `d_results` → Stores cracked words.
  - `d_found_flags` → Flags to indicate success.

---

## **7. Running the Brute-Force Attack**
```cpp
    int blockSize = 256;
    for (int length = 1; length <= MAX_WORD_LENGTH; length++) {
        int numWords = pow(ALPHABET_SIZE, length);
        int numBlocks = (numWords + blockSize - 1) / blockSize;
        
        printf("Trying %d-letter words...\n", length);
        sha256_bruteforce<<<numBlocks, blockSize>>>(d_target_hashes, num_hashes, d_results, d_found_flags, length);
        cudaDeviceSynchronize();
```
- Iterates over **increasing word lengths**.
- **Kernel launch:**
  ```cpp
  sha256_bruteforce<<<numBlocks, blockSize>>>(...);
  ```
  - Each **CUDA block** processes `blockSize` words.
  - Uses **grid-stride parallelism** to explore **entire search space**.

---

## **8. Checking Results**
```cpp
    for (int i = 0; i < num_hashes; i++) {
        if (h_found_flags[i]) {
            printf("Hash %s -> Found: %s\n", argv[i + 1], h_results[i]);
        } else {
            printf("Hash %s -> No match found.\n", argv[i + 1]);
        }
    }
```
- Prints **cracked words** or reports failure.

---

# **Parallel Programming in This Code**
| **Feature** | **How It Works** |
|------------|-----------------|
| **Massive Parallelism** | Each **CUDA thread** processes a **unique word** simultaneously. |
| **Thread Indexing** | Uses `blockIdx.x * blockDim.x + threadIdx.x` to assign work. |
| **Shared Memory** | No shared memory is used (but could be optimized). |
| **Global Memory Access** | Target hashes and results are stored in **global memory**. |
| **Memory Transfers** | Uses `cudaMemcpy` to **move data** between CPU and GPU. |

### **Why is CUDA better than CPU here?**
- The CPU **sequentially hashes words**, making brute force **extremely slow**.
- The **GPU hashes thousands of words at the same time**, making it **much faster**.

---
