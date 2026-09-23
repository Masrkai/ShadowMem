#ifndef SHADOWMEM_ESP32_H
#define SHADOWMEM_ESP32_H

/*
 * ShadowMem_esp32.h ESP32 platform layer (Arduino-ESP32 core or ESP-IDF).
 *
 * Include this (not ShadowMem_core.h directly) on ESP32. It supplies the
 * platform hooks ShadowMem_core.h declares, using:
 *   - heap_caps_malloc(..., MALLOC_CAP_INTERNAL) so secret buffers stay
 *     in internal SRAM rather than external PSRAM where available,
 *   - esp_random() (hardware RNG) instead of rand()/time(), which is a
 *     genuine security upgrade over the desktop seeding path,
 *   - no-op lock/unlock, since ESP32 has no swap/paging at all there
 *     is no disk in the memory hierarchy to page secrets out to, so the
 *     property mlock chases on desktop already holds unconditionally,
 *   - explicit_bzero where the underlying newlib/ESP-IDF version
 *     provides it, falling back to a volatile loop otherwise.
 *
 * NOT SUPPORTED: Arduino Uno / AVR. That hardware (2KB SRAM, no OS, no
 * heap sized for variable-length dynamic allocation of secrets) needs a
 * fundamentally different, fixed-buffer design, not a third hook file
 * plugged into this same core. Attempting to stretch this abstraction
 * onto AVR would misrepresent what's actually safe on that hardware.
 *
 * THREAT MODEL read before use:
 *  - XOR obfuscation is not encryption; see ShadowMem_core.h.
 *  - No swap exists to protect against, but a crash dump or OTA/serial
 *    debug log taken while a secret is in its decrypted window (inside
 *    shadowmem_string_print or between decrypt_temp/encrypt_temp) can
 *    still expose it this is the embedded analogue of a core dump.
 *  - Repeated malloc/free/realloc cycles for secrets on a long-uptime
 *    device can fragment the heap over time; if this runs for months,
 *    consider a static/pool-allocated buffer instead of shadowmem_input's
 *    growth strategy.
 *
 * REQUIRES: ESP-IDF's esp_random() and esp_heap_caps.h. Under Arduino-
 * ESP32, these are available via the underlying ESP-IDF headers; both
 * esp_random.h and esp_heap_caps.h ship with the Arduino-ESP32 core.
 */

#include <stddef.h>
#include <string.h>

#include "esp_random.h"
#include "esp_heap_caps.h"

#include "ShadowMem_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Platform hooks required by ShadowMem_core.h
 * ==========================================================================*/
void* shadowmem_platform_malloc(size_t n) {
    /* Force internal SRAM: secrets should not land in external PSRAM,
     * which sits on a separate, more exposed memory bus on modules that
     * have it. Falls back to regular malloc only if internal alloc fails
     * (e.g. under memory pressure), so the library degrades rather than
     * simply failing outright callers can inspect .buffer for NULL
     * either way. */
    void* p = heap_caps_malloc(n, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!p) p = malloc(n);
    return p;
}

void shadowmem_platform_free(void* p) {
    heap_caps_free(p);
}

void* shadowmem_platform_realloc(void* p, size_t n) {
    void* np = heap_caps_realloc(p, n, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!np) np = realloc(p, n);
    return np;
}

void shadowmem_secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
#if defined(__GLIBC__) || defined(__NEWLIB__)
    /* Recent ESP-IDF newlib versions provide explicit_bzero; if yours
     * doesn't, this branch won't compile drop to the #else manually
     * or update ESP-IDF. */
    explicit_bzero(ptr, len);
#else
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    for (size_t i = 0; i < len; ++i) p[i] = 0;
#endif
}

void shadowmem_lock_buffer(void* ptr, size_t len) {
    /* No-op: ESP32 has no swap/paging, so there is nothing to lock
     * against. The property mlock() chases on desktop already holds
     * unconditionally here. */
    (void)ptr; (void)len;
}

void shadowmem_unlock_buffer(void* ptr, size_t len) {
    (void)ptr; (void)len;
}

void shadowmem_fill_random(unsigned char* out, size_t len) {
    /* esp_random() is backed by the ESP32's hardware RNG (thermal noise
     * + RF, when Wi-Fi/BT is active it's even stronger) genuinely
     * better entropy than the desktop rand()/time() seeding path. */
    size_t i = 0;
    while (i < len) {
        uint32_t r = esp_random();
        size_t chunk = (len - i) < 4 ? (len - i) : 4;
        memcpy(out + i, &r, chunk);
        i += chunk;
    }
}

/* ==========================================================================
 * ESP32-only: masked Serial input (Arduino-ESP32 core)
 *
 * Only compiled when building under the Arduino framework, since it
 * needs the Serial object. Pure ESP-IDF projects (no Arduino component)
 * should implement their own UART read loop and call
 * shadowmem_string_from_raw() directly instead of this function.
 * ==========================================================================*/
#ifdef ARDUINO
#include <Arduino.h>

static inline ShadowMem_String shadowmem_input(int mask, int* out_truncated) {
    size_t capacity = 64;
    size_t size = 0;
    int truncated = 0;
    char* raw = (char*)shadowmem_platform_malloc(capacity);
    if (out_truncated) *out_truncated = 0;

    if (!raw) {
        ShadowMem_String empty;
        empty.buffer = NULL; empty.size = 0; empty.capacity = 0;
        empty.key = NULL; empty.locked = 0;
        return empty;
    }

    while (true) {
        if (!Serial.available()) {
            continue; /* poll; caller's loop owns any watchdog/yield needs */
        }
        int ch = Serial.read();

        if (ch == '\r' || ch == '\n') break;

        if (ch == 127 || ch == 8) { /* backspace/delete */
            if (size > 0) {
                size--;
                if (mask) Serial.print("\b \b");
            }
            continue;
        }

        if (size + 1 >= capacity) {
            size_t new_capacity = capacity * 2;
            char* new_raw = (char*)shadowmem_platform_realloc(raw, new_capacity);
            if (!new_raw) { truncated = 1; break; }
            raw = new_raw;
            capacity = new_capacity;
        }
        raw[size++] = (char)ch;
        if (mask) Serial.print('*');
    }
    Serial.println();

    ShadowMem_String secure = shadowmem_string_from_raw(raw, size);

    shadowmem_secure_zero(raw, capacity);
    shadowmem_platform_free(raw);

    if (out_truncated) *out_truncated = truncated;
    return secure;
}

static inline void shadowmem_string_print(ShadowMem_String* s) {
    if (!s || !s->buffer) return;
    shadowmem_string_toggle(s);
    for (size_t i = 0; i < s->size; ++i) {
        Serial.write(s->buffer[i]);
    }
    shadowmem_string_toggle(s);
}
#endif /* ARDUINO */

#ifdef __cplusplus
}
#endif

#endif /* SHADOWMEM_ESP32_H */
