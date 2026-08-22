#ifndef SHADOWMEM_H
#define SHADOWMEM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// 1. Portable Getch (Cross-Platform Non-Echoing Character Input)
// ============================================================================
static inline int shadowmem_portable_getch(void) {
#ifdef _WIN32
    return _getch();
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    int ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
#endif
}

// ============================================================================
// 2. Random Key Generator
// ============================================================================
static inline char shadowmem_random_key(void) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)&seeded);
        seeded = 1;
    }
    int val = (rand() % 255) + 1;
    return (char)val;
}

// ============================================================================
// 3. Secure String Container (C Structure)
// ============================================================================
typedef struct {
    char* buffer;
    size_t size;
    size_t capacity;
    char key;
} ShadowMem_String;

// Toggle encryption/decryption in-place
static inline void shadowmem_string_toggle(ShadowMem_String* s) {
    if (!s || !s->buffer) return;
    for (size_t i = 0; i < s->size; ++i) {
        s->buffer[i] ^= s->key;
    }
}

// Initialize secure string from raw plaintext bytes
static inline ShadowMem_String shadowmem_string_from_raw(const char* raw, size_t len) {
    ShadowMem_String s;
    s.key = shadowmem_random_key();
    s.size = len;
    s.capacity = len > 0 ? len : 1;
    s.buffer = (char*)malloc(s.capacity);
    if (s.buffer) {
        memcpy(s.buffer, raw, len);
        shadowmem_string_toggle(&s); // Encrypt immediately
    } else {
        s.size = 0;
        s.capacity = 0;
    }
    return s;
}

// Securely wipe and free memory
static inline void shadowmem_string_free(ShadowMem_String* s) {
    if (!s) return;
    if (s->buffer && s->capacity > 0) {
        volatile char* p = (volatile char*)s->buffer;
        for (size_t i = 0; i < s->capacity; ++i) {
            p[i] = 0;
        }
        free(s->buffer);
        s->buffer = NULL;
    }
    s->size = 0;
    s->capacity = 0;
}

// Automatic cleanup macro for GCC/Clang (RAII simulation in C)
#if defined(__GNUC__) || defined(__CLANG__)
static inline void shadowmem_string_cleanup(ShadowMem_String* s) {
    shadowmem_string_free(s);
}
#define SM_SECURE __attribute__((cleanup(shadowmem_string_cleanup)))
#else
#define SM_SECURE
#endif

// Print secure string safely (decrypts temporarily, prints, re-encrypts)
static inline void shadowmem_string_print(ShadowMem_String* s) {
    if (!s || !s->buffer) return;
    shadowmem_string_toggle(s); // Decrypt
    fwrite(s->buffer, 1, s->size, stdout);
    shadowmem_string_toggle(s); // Re-encrypt
}

// Get temporary plaintext
static inline char* shadowmem_string_decrypt_temp(ShadowMem_String* s) {
    if (!s || !s->buffer) return NULL;
    shadowmem_string_toggle(s);
    return s->buffer;
}

static inline void shadowmem_string_encrypt_temp(ShadowMem_String* s) {
    if (!s || !s->buffer) return;
    shadowmem_string_toggle(s);
}

// ============================================================================
// 4. Secure Runtime Input
// ============================================================================
static inline ShadowMem_String shadowmem_input(int mask) {
    size_t capacity = 64;
    size_t size = 0;
    char* raw = (char*)malloc(capacity);
    if (!raw) {
        ShadowMem_String empty = {NULL, 0, 0, 0};
        return empty;
    }

    int ch;
    while ((ch = shadowmem_portable_getch()) != '\r' && ch != '\n') {
        if (ch == '\b' || ch == 127) {
            if (size > 0) {
                size--;
                if (mask) {
                    printf("\b \b");
                    fflush(stdout);
                }
            }
        } else {
            if (size + 1 >= capacity) {
                capacity *= 2;
                char* new_raw = (char*)realloc(raw, capacity);
                if (!new_raw) break;
                raw = new_raw;
            }
            raw[size++] = (char)ch;
            if (mask) {
                putchar('*');
                fflush(stdout);
            }
        }
    }
    putchar('\n');

    // Create secure string
    ShadowMem_String secure = shadowmem_string_from_raw(raw, size);

    // Wipe raw input buffer traces from memory
    volatile char* p = (volatile char*)raw;
    for (size_t i = 0; i < capacity; ++i) {
        p[i] = 0;
    }
    free(raw);

    return secure;
}

#ifdef __cplusplus
}
#endif

#endif // SHADOWMEM_H
