#ifndef SHADOWMEM_CORE_H
#define SHADOWMEM_CORE_H

/*
 * ShadowMem_core.h platform-agnostic core.
 *
 * This file contains ONLY logic that has identical meaning everywhere:
 * the struct layout, the XOR obfuscation math, and buffer bookkeeping
 * that doesn't touch the OS. It deliberately contains NO I/O, NO
 * allocator calls, and NO memory-locking calls those differ per
 * platform and are supplied by a platform header (ShadowMem_desktop.h
 * or ShadowMem_esp32.h) that includes this file first and then defines
 * the platform hooks this core expects.
 *
 * HONEST SCOPE (applies everywhere this is used): XOR obfuscation,
 * even multi-byte with a separately allocated key, is NOT cryptography.
 * It denies a casual memory/core-dump scan, not a deliberate attacker
 * with memory read access. See each platform header's own notes for
 * platform-specific caveats (swap/paging on desktop; heap region and
 * hardware RNG on ESP32; AVR is not supported by this library at all).
 *
 * -----------------------------------------------------------------------
 * Platform hook contract a platform header MUST provide these before
 * including this file's function bodies are used (they are declared
 * here, defined per-platform):
 *
 *   void*  shadowmem_platform_malloc(size_t n);
 *   void   shadowmem_platform_free(void* p);
 *   void*  shadowmem_platform_realloc(void* p, size_t n);
 *   void   shadowmem_secure_zero(void* ptr, size_t len);
 *   void   shadowmem_lock_buffer(void* ptr, size_t len);   // best-effort
 *   void   shadowmem_unlock_buffer(void* ptr, size_t len); // best-effort
 *   void   shadowmem_fill_random(unsigned char* out, size_t len);
 *   int    shadowmem_portable_getch(void);                 // may be unused
 *                                                           // on platforms
 *                                                           // with no
 *                                                           // interactive
 *                                                           // input path
 * -----------------------------------------------------------------------
 */

#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define SHADOWMEM_HAVE_CLEANUP 1
#else
#define SHADOWMEM_HAVE_CLEANUP 0
#endif

#define SHADOWMEM_KEY_LEN 32

/* ==========================================================================
 * Platform hooks (declared here, defined by the platform header)
 * ==========================================================================*/
void* shadowmem_platform_malloc(size_t n);
void  shadowmem_platform_free(void* p);
void* shadowmem_platform_realloc(void* p, size_t n);
void  shadowmem_secure_zero(void* ptr, size_t len);
void  shadowmem_lock_buffer(void* ptr, size_t len);
void  shadowmem_unlock_buffer(void* ptr, size_t len);
void  shadowmem_fill_random(unsigned char* out, size_t len);

/* ==========================================================================
 * Secure string container identical layout on every platform.
 * ==========================================================================*/
typedef struct {
    unsigned char* buffer;
    size_t size;
    size_t capacity;
    unsigned char* key;   /* SHADOWMEM_KEY_LEN bytes, separately allocated */
    int locked;           /* whether lock_buffer was attempted (not a guarantee) */
} ShadowMem_String;

/* XOR toggle is pure math identical everywhere. */
static inline void shadowmem_string_toggle(ShadowMem_String* s) {
    if (!s || !s->buffer || !s->key) return;
    for (size_t i = 0; i < s->size; ++i) {
        s->buffer[i] ^= s->key[i % SHADOWMEM_KEY_LEN];
    }
}

/* Construction/destruction only call the platform hooks above, so the
 * logic is written once here and behaves identically everywhere the
 * hooks are correctly implemented. */
static inline ShadowMem_String shadowmem_string_from_raw(const char* raw, size_t len) {
    ShadowMem_String s;
    s.buffer = NULL;
    s.size = 0;
    s.capacity = 0;
    s.key = NULL;
    s.locked = 0;

    if (len > 0 && !raw) {
        return s; /* NULL raw with nonzero len is a caller bug; fail safe */
    }

    s.key = (unsigned char*)shadowmem_platform_malloc(SHADOWMEM_KEY_LEN);
    if (!s.key) return s;
    shadowmem_fill_random(s.key, SHADOWMEM_KEY_LEN);

    s.capacity = len > 0 ? len : 1;
    s.buffer = (unsigned char*)shadowmem_platform_malloc(s.capacity);
    if (!s.buffer) {
        shadowmem_secure_zero(s.key, SHADOWMEM_KEY_LEN);
        shadowmem_platform_free(s.key);
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
    s.locked = 1;

    shadowmem_string_toggle(&s); /* encrypt immediately */
    return s;
}

static inline void shadowmem_string_free(ShadowMem_String* s) {
    if (!s) return;
    if (s->buffer) {
        shadowmem_secure_zero(s->buffer, s->capacity);
        if (s->locked) shadowmem_unlock_buffer(s->buffer, s->capacity);
        shadowmem_platform_free(s->buffer);
        s->buffer = NULL;
    }
    if (s->key) {
        shadowmem_secure_zero(s->key, SHADOWMEM_KEY_LEN);
        if (s->locked) shadowmem_unlock_buffer(s->key, SHADOWMEM_KEY_LEN);
        shadowmem_platform_free(s->key);
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

static inline int shadowmem_string_equals(ShadowMem_String* s, const char* other, size_t other_len) {
    if (!s || !s->buffer) return 0;
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

#ifdef __cplusplus
}
#endif

#endif /* SHADOWMEM_CORE_H */
