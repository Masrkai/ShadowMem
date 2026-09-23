#ifndef SHADOWMEM_DESKTOP_H
#define SHADOWMEM_DESKTOP_H

/* IMPORTANT INCLUDE-ORDER REQUIREMENT (glibc/Linux only):
 * explicit_bzero's prototype is gated behind glibc feature-test macros
 * that must be set before the FIRST system header is included anywhere
 * in the translation unit not just before this file's own <string.h>
 * include. If your .c file includes <string.h> (or anything that pulls
 * it in transitively) before this header, #define _GNU_SOURCE yourself
 * as the very first line of that file, or include ShadowMem_desktop.h
 * first. The #define below only helps when this header is the first
 * thing included; it cannot retroactively widen an already-included
 * <string.h>. If neither is possible, this file falls back to a
 * portable volatile-loop wipe automatically see shadowmem_secure_zero
 * below so correctness is preserved either way, just not the
 * stronger glibc primitive. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

/*
 * ShadowMem_desktop.h POSIX (Linux/macOS) and Windows platform layer.
 *
 * Include this (not ShadowMem_core.h directly) from desktop C/C++ code.
 * It supplies the platform hooks ShadowMem_core.h declares, using
 * termios-based raw terminal input, malloc/realloc/free, mlock/VirtualLock
 * for best-effort swap protection, and explicit_bzero/SecureZeroMemory/
 * memset_s for guaranteed-not-elided wiping where available.
 *
 * THREAT MODEL read before use:
 *  - XOR obfuscation is not encryption; see ShadowMem_core.h.
 *  - mlock/VirtualLock are best-effort: they commonly fail silently
 *    without elevated privileges or inside containers. Check
 *    ShadowMem_String.locked if you need to know an attempt was made
 *    it does not mean the OS guaranteed the memory stays off swap.
 *  - Compiled binaries still leak hardcoded string literals via `strings`
 *    at the executable level; that is a different problem from runtime
 *    memory hygiene and this library does not address it. Use a
 *    dedicated obfuscator (e.g. https://github.com/adamyaxley/Obfuscate)
 *    for that.
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

#include "ShadowMem_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Platform hooks required by ShadowMem_core.h
 * ==========================================================================*/
void* shadowmem_platform_malloc(size_t n) { return malloc(n); }
void  shadowmem_platform_free(void* p) { free(p); }
void* shadowmem_platform_realloc(void* p, size_t n) { return realloc(p, n); }

void shadowmem_secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#elif (defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)) \
      || (defined(__GLIBC__) && defined(__USE_GNU))
    /* __USE_GNU (not our own _GNU_SOURCE define) is the signal glibc's
     * <features.h> actually sets, and only when _GNU_SOURCE was defined
     * before the first system header was included anywhere in this
     * translation unit. Checking our own _GNU_SOURCE macro here would
     * be wrong: we define it ourselves further up in this file, so it
     * is always set by the time we reach this point regardless of
     * whether it arrived in time to affect <string.h>'s declarations
     * checking it would silently take this branch even when the
     * prototype isn't actually visible, producing an implicit-
     * declaration warning instead of falling back safely. __USE_GNU
     * reflects glibc's own answer to that question. BSD/Apple libc
     * expose explicit_bzero unconditionally, no feature-test macro
     * needed. */
    explicit_bzero(ptr, len);
#else
    /* Portable fallback: still correct, just without the platform's
     * guaranteed-not-elided primitive. This is the path taken whenever
     * the _GNU_SOURCE include-order requirement above wasn't met. */
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    for (size_t i = 0; i < len; ++i) p[i] = 0;
#endif
}

void shadowmem_lock_buffer(void* ptr, size_t len) {
#if defined(_WIN32)
    VirtualLock(ptr, len);
#elif defined(__unix__) || defined(__APPLE__)
    mlock(ptr, len); /* best-effort; ignore failure (e.g. no privilege) */
#else
    (void)ptr; (void)len;
#endif
}

void shadowmem_unlock_buffer(void* ptr, size_t len) {
#if defined(_WIN32)
    VirtualUnlock(ptr, len);
#elif defined(__unix__) || defined(__APPLE__)
    munlock(ptr, len);
#else
    (void)ptr; (void)len;
#endif
}

void shadowmem_fill_random(unsigned char* out, size_t len) {
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
 * Desktop-only: interactive terminal input
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

/* Fixes vs. the original: explicit EOF/Ctrl-D handling; realloc failure
 * is reported via out_truncated instead of silently dropping data. */
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

    int ch;
    while (1) {
        ch = shadowmem_portable_getch();

        if (ch == EOF) break;
        if (ch == '\r' || ch == '\n') break;

        if (ch == '\b' || ch == 127) {
            if (size > 0) {
                size--;
                if (mask) { printf("\b \b"); fflush(stdout); }
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
        if (mask) { putchar('*'); fflush(stdout); }
    }
    putchar('\n');

    ShadowMem_String secure = shadowmem_string_from_raw(raw, size);

    shadowmem_secure_zero(raw, capacity);
    shadowmem_platform_free(raw);

    if (out_truncated) *out_truncated = truncated;
    return secure;
}

static inline void shadowmem_string_print(ShadowMem_String* s) {
    if (!s || !s->buffer) return;
    shadowmem_string_toggle(s);
    fwrite(s->buffer, 1, s->size, stdout);
    shadowmem_string_toggle(s);
}

#ifdef __cplusplus
}
#endif

#endif /* SHADOWMEM_DESKTOP_H */
