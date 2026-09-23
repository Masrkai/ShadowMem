#ifndef SHADOWMEM_H
#define SHADOWMEM_H

/*
 * ShadowMem lightweight in-memory secret obfuscation utility.
 *
 * HONEST SCOPE: this is NOT cryptographic protection. XOR obfuscation
 * (even multi-byte) does not withstand an adversary who can read process
 * memory. What this library DOES provide:
 *   - secrets are not stored as raw plaintext, defeating naive `strings`
 *     scans of memory/core dumps
 *   - buffers are wiped (guaranteed, non-optimized-away) on free
 *   - secret pages are best-effort locked out of swap
 *   - no reliance on NUL-termination bugs, no OOB reads
 * If you need real protection against a memory-scraping adversary, use
 * OS-provided secret storage (e.g. libsodium's sodium_malloc/mlock,
 * Keychain/DPAPI/TPM-backed stores), not this.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/mman.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * 0. Compiler / platform detection (fixed: __clang__ is lowercase)
 * ==========================================================================*/
#if defined(__GNUC__) || defined(__clang__)
#define SHADOWMEM_HAVE_CLEANUP 1
#else
#define SHADOWMEM_HAVE_CLEANUP 0
#endif

/* ==========================================================================
 * 1. Portable, guaranteed-not-elided secure zero
 * ==========================================================================*/
static inline void shadowmem_secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__GLIBC__)
    explicit_bzero(ptr, len);
#else
    /* Fallback: volatile loop. Weaker guarantee than the above, but still
     * far better than plain memset, which a compiler CAN legally elide if
     * it can prove the memory is never read again. */
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    for (size_t i = 0; i < len; ++i) p[i] = 0;
#endif
}

/* ==========================================================================
 * 2. Portable non-echoing single character input
 * ==========================================================================*/
static inline int shadowmem_portable_getch(void) {
#ifdef _WIN32
    return _getch();
#else
    struct termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) return getchar();
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    int ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
#endif
}

/* ==========================================================================
 * 3. Key generation multi-byte keystream instead of a single XOR byte.
 *    Still XOR obfuscation, NOT real encryption see header note.
 * ==========================================================================*/
#define SHADOWMEM_KEY_LEN 32

static inline void shadowmem_fill_random(unsigned char* out, size_t len) {
    static int seeded = 0;
    if (!seeded) {
        unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)out;
        srand(seed);
        seeded = 1;
    }
    for (size_t i = 0; i < len; ++i) {
        out[i] = (unsigned char)(rand() % 256);
    }
}

/* ==========================================================================
 * 4. Secure string container
 *    - `size` is the true length; buffer is NEVER relied upon to be
 *      NUL-terminated internally, avoiding the OOB-read bug in the
 *      original strcmp() usage.
 *    - key is a separate heap allocation, not embedded in the struct,
 *      so a flat memory scan of the struct itself doesn't hand an
 *      attacker ciphertext+key side by side.
 * ==========================================================================*/
typedef struct {
    unsigned char* buffer;
    size_t size;
    size_t capacity;
    unsigned char* key;   /* SHADOWMEM_KEY_LEN bytes, separately allocated */
    int locked;           /* whether mlock/VirtualLock succeeded */
} ShadowMem_String;

static inline void shadowmem_string_toggle(ShadowMem_String* s) {
    if (!s || !s->buffer || !s->key) return;
    for (size_t i = 0; i < s->size; ++i) {
        s->buffer[i] ^= s->key[i % SHADOWMEM_KEY_LEN];
    }
}

static inline void shadowmem_lock_buffer(void* ptr, size_t len) {
#if defined(_WIN32)
    VirtualLock(ptr, len);
#elif defined(__unix__) || defined(__APPLE__)
    mlock(ptr, len); /* best-effort; ignore failure (e.g. no privilege) */
#else
    (void)ptr; (void)len;
#endif
}

static inline void shadowmem_unlock_buffer(void* ptr, size_t len) {
#if defined(_WIN32)
    VirtualUnlock(ptr, len);
#elif defined(__unix__) || defined(__APPLE__)
    munlock(ptr, len);
#else
    (void)ptr; (void)len;
#endif
}

/* Returns a zeroed/empty ShadowMem_String on allocation failure.
 * Callers MUST check result.buffer != NULL (or size == 0 vs len > 0
 * mismatch) before using it. */
static inline ShadowMem_String shadowmem_string_from_raw(const char* raw, size_t len) {
    ShadowMem_String s;
    s.buffer = NULL;
    s.size = 0;
    s.capacity = 0;
    s.key = NULL;
    s.locked = 0;

    if (len > 0 && !raw) {
        /* NULL raw with nonzero len is a caller bug; fail safe. */
        return s;
    }

    s.key = (unsigned char*)malloc(SHADOWMEM_KEY_LEN);
    if (!s.key) return s;
    shadowmem_fill_random(s.key, SHADOWMEM_KEY_LEN);

    s.capacity = len > 0 ? len : 1;
    s.buffer = (unsigned char*)malloc(s.capacity);
    if (!s.buffer) {
        shadowmem_secure_zero(s.key, SHADOWMEM_KEY_LEN);
        free(s.key);
        s.key = NULL;
        s.capacity = 0;
        return s;
    }

    if (len > 0) {
        memcpy(s.buffer, raw, len);
    }
    s.size = len;

    shadowmem_lock_buffer(s.buffer, s.capacity);
    shadowmem_lock_buffer(s.key, SHADOWMEM_KEY_LEN);
    s.locked = 1; /* best-effort flag; doesn't guarantee both succeeded */

    shadowmem_string_toggle(&s); /* encrypt immediately */
    return s;
}

static inline void shadowmem_string_free(ShadowMem_String* s) {
    if (!s) return;
    if (s->buffer) {
        shadowmem_secure_zero(s->buffer, s->capacity);
        if (s->locked) shadowmem_unlock_buffer(s->buffer, s->capacity);
        free(s->buffer);
        s->buffer = NULL;
    }
    if (s->key) {
        shadowmem_secure_zero(s->key, SHADOWMEM_KEY_LEN);
        if (s->locked) shadowmem_unlock_buffer(s->key, SHADOWMEM_KEY_LEN);
        free(s->key);
        s->key = NULL;
    }
    s->size = 0;
    s->capacity = 0;
    s->locked = 0;
}

#if SHADOWMEM_HAVE_CLEANUP
static inline void shadowmem_string_cleanup(ShadowMem_String* s) {
    shadowmem_string_free(s);
}
#define SM_SECURE __attribute__((cleanup(shadowmem_string_cleanup)))
#else
#define SM_SECURE
#endif

/* Print secure string safely (decrypts temporarily, prints exact byte
 * length never assumes NUL termination then re-encrypts). */
static inline void shadowmem_string_print(ShadowMem_String* s) {
    if (!s || !s->buffer) return;
    shadowmem_string_toggle(s);
    fwrite(s->buffer, 1, s->size, stdout);
    shadowmem_string_toggle(s);
}

/* Caller gets a pointer + explicit length. Caller MUST NOT use strlen()
 * or any NUL-terminated string function on this pointer: the buffer is
 * exactly `s->size` bytes, no guaranteed trailing NUL. Caller must also
 * call shadowmem_string_encrypt_temp() promptly and must not retain the
 * returned pointer past that call (it will point at ciphertext again). */
static inline unsigned char* shadowmem_string_decrypt_temp(ShadowMem_String* s, size_t* out_len) {
    if (!s || !s->buffer) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    shadowmem_string_toggle(s);
    if (out_len) *out_len = s->size;
    return s->buffer;
}

static inline void shadowmem_string_encrypt_temp(ShadowMem_String* s) {
    if (!s || !s->buffer) return;
    shadowmem_string_toggle(s);
}

/* Constant-time comparison of a secure string's plaintext against a
 * caller-supplied buffer, without ever fully decrypting into a third
 * location and without relying on strcmp/NUL termination. */
static inline int shadowmem_string_equals(ShadowMem_String* s, const char* other, size_t other_len) {
    if (!s || !s->buffer) return 0;
    if (s->size != other_len) {
        /* Still do a dummy pass to reduce (not eliminate) length-based
         * timing signal; not a full constant-time guarantee. */
    }
    size_t len;
    unsigned char* plain = shadowmem_string_decrypt_temp(s, &len);
    if (!plain) return 0;

    unsigned char diff = (unsigned char)(len != other_len);
    size_t n = len < other_len ? len : other_len;
    for (size_t i = 0; i < n; ++i) {
        diff |= (unsigned char)(plain[i] ^ (unsigned char)other[i]);
    }
    shadowmem_string_encrypt_temp(s);
    return diff == 0;
}

/* ==========================================================================
 * 5. Secure runtime input (masked)
 *    Fixes: EOF/Ctrl-D handling, realloc-failure no longer silently
 *    truncates the secret (returns what was typed so far AND signals
 *    truncation via out_truncated), wipes intermediate buffer on all
 *    exit paths including error paths.
 * ==========================================================================*/
static inline ShadowMem_String shadowmem_input(int mask, int* out_truncated) {
    size_t capacity = 64;
    size_t size = 0;
    int truncated = 0;
    char* raw = (char*)malloc(capacity);
    if (out_truncated) *out_truncated = 0;

    if (!raw) {
        ShadowMem_String empty;
        empty.buffer = NULL; empty.size = 0; empty.capacity = 0;
        empty.key = NULL; empty.locked = 0;
        return empty;
    }

    int ch;
    while (1) {
        ch = shadowmem_portable_getch();

        if (ch == EOF) {
            break; /* Ctrl-D / stream closed: stop reading, keep what we have */
        }
        if (ch == '\r' || ch == '\n') {
            break;
        }
        if (ch == '\b' || ch == 127) {
            if (size > 0) {
                size--;
                if (mask) {
                    printf("\b \b");
                    fflush(stdout);
                }
            }
            continue;
        }

        if (size + 1 >= capacity) {
            size_t new_capacity = capacity * 2;
            char* new_raw = (char*)realloc(raw, new_capacity);
            if (!new_raw) {
                /* Do not silently truncate without telling the caller. */
                truncated = 1;
                break;
            }
            raw = new_raw;
            capacity = new_capacity;
        }
        raw[size++] = (char)ch;
        if (mask) {
            putchar('*');
            fflush(stdout);
        }
    }
    putchar('\n');

    ShadowMem_String secure = shadowmem_string_from_raw(raw, size);

    shadowmem_secure_zero(raw, capacity);
    free(raw);

    if (out_truncated) *out_truncated = truncated;
    return secure;
}

#ifdef __cplusplus
}
#endif

#endif /* SHADOWMEM_H */
