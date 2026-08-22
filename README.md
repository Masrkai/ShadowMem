# ShadowMem

**ShadowMem (`ShadowMem.h`)** is a lightweight, header-only C library designed for secure memory and string management (in memory not binary). It protects sensitive data such as passwords, cryptographic keys, authentication tokens, and PII while resident in RAM, mitigating risks from memory dumps, core dumps, or casual inspection.

---

## Features

- **In-Memory Encryption:** Strings are automatically encrypted in memory using XOR encryption with a randomized key generated per container instance.
- **Secure Memory Wiping:** Automatically overwrites sensitive buffers with zeros using volatile memory stores upon freeing or cleanup, preventing residual data remnants in RAM.
- **RAII-Style Automatic Cleanup (GCC/Clang):** Leverages `__attribute__((cleanup))` to guarantee automatic zeroing and deallocation when secure strings go out of scope.
- **Secure Runtime Input:** Cross-platform secure input routine (`shadowmem_input`) supporting masked character entry (`*` echoing or hidden), backspace handling, and dynamic allocation.
- **Cross-Platform Compatibility:** Works seamlessly across POSIX (Linux/macOS) and Windows systems without external dependencies.
- **Header-Only:** Drop `ShadowMem.h` directly into any C99+ project.

---

## API Reference

### Data Structures

- **`ShadowMem_String`**: Container storing the encrypted buffer, string size, capacity, and encryption key.

### Core Functions & Macros

- `ShadowMem_String shadowmem_string_from_raw(const char* raw, size_t len)`: Encrypts and stores raw plaintext bytes into a secure container.
- `void shadowmem_string_free(ShadowMem_String* s)`: Securely wipes the underlying buffer with zeros and frees allocated memory.
- `void shadowmem_string_print(ShadowMem_String* s)`: Temporarily decrypts, prints to `stdout`, and re-encrypts the string.
- `char* shadowmem_string_decrypt_temp(ShadowMem_String* s)`: Temporarily decrypts the buffer for direct read access.
- `void shadowmem_string_encrypt_temp(ShadowMem_String* s)`: Re-encrypts the buffer after temporary access.
- `ShadowMem_String shadowmem_input(int mask)`: Captures secure user input from the console (set `mask = 1` for password asterisk masking, `0` for hidden input).
- `SM_SECURE`: Macro enabling automatic scope-based cleanup on GCC and Clang compilers.

---

## Quick Start Guide

### Example Usage

```c
#include <stdio.h>
#include "ShadowMem.h"

int main(void) {
    // 1. Create a secure string from raw input
    const char* secret = "SuperSecretPassword123";
    ShadowMem_String secure_str = shadowmem_string_from_raw(secret, strlen(secret));

    // 2. Print safely without exposing raw buffer permanently
    printf("Encrypted secure string: ");
    shadowmem_string_print(&secure_str);
    printf("\n");

    // 3. Secure automatic cleanup using RAII (GCC/Clang)
#if defined(__GNUC__) || defined(__CLANG__)
    {
        SM_SECURE ShadowMem_String pass = shadowmem_input(1); // Masked user input
        printf("Password captured securely.\n");
    } // Automatically wiped and freed here!
#endif

    // 4. Manual cleanup
    shadowmem_string_free(&secure_str);
    return 0;
}
```

---

## Building and Running Tests

To build and run the test suite:

```bash
gcc test_shadowmem.c -o test_shadowmem -std=c99 -Wall -Wextra
./test_shadowmem
```

---

## Why ShadowMem?

While exploring existing secure memory concepts in C, many available implementations suffered from portability issues, lack of GCC/Clang support, and insufficient maintenance for supply-chain or production environments.

ShadowMem was created as a clean-room, robust, header-only library designed specifically to provide reliable in-memory encryption, secure zeroing, and RAII cleanup for C99+ projects without external dependencies or compilation hurdles.

## Note

!!!!THIS IS NOT A SILVER BULLET

if you compile this and you have a hardcoded string this is not a silver bullet nor it claims to be.
this library is working at MEMORY level, at executable level you can still pull the `strings` utility and see your hardcoded values
if you are planning to obfescate those go find an obfescator like:

- <https://github.com/adamyaxley/Obfuscate/blob/master/obfuscate.h>

i do not hold any liability for you using AI and not understanding what does this do nor if cridentials got leaked because of negligence.
