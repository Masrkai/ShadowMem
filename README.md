# ShadowMem

**ShadowMem** is a lightweight, header-only C library for reducing the exposure of sensitive data (passwords, tokens, key material, PII) while it's resident in RAM. It keeps secrets out of plaintext form at rest in memory, wipes buffers on free using a guaranteed-not-elided zeroing routine where the platform supports it, and best-effort locks secret pages out of swap.

> **This is obfuscation and hygiene, not cryptography.** See the [Threat Model](#threat-model--honest-limitations) section before using this for anything that matters.

## File layout

The library is split into a shared core plus one thin platform layer per target, so platform-specific I/O/allocator/locking code never has to duplicate the struct layout or the XOR bookkeeping:

- **`ShadowMem_core.h`** platform-agnostic: the `ShadowMem_String` struct, the XOR toggle, construction/destruction logic. Contains no I/O, no direct allocator calls, and no OS memory-locking calls; it calls a small set of platform hooks (`shadowmem_platform_malloc`, `shadowmem_secure_zero`, `shadowmem_lock_buffer`, `shadowmem_fill_random`, etc.) that each platform header defines. Never include this directly in application code.
- **`ShadowMem_desktop.h`** POSIX (Linux/macOS) and Windows. Include this from desktop C/C++ code. Supplies `malloc`/`realloc`/`free`, `mlock`/`VirtualLock`, `explicit_bzero`/`SecureZeroMemory`, termios-based masked terminal input (`shadowmem_input`), and `shadowmem_string_print`.
- **`ShadowMem_esp32.h`** ESP32 (Arduino-ESP32 core or ESP-IDF). Include this instead of the desktop header when targeting ESP32. Supplies `heap_caps_malloc` pinned to internal SRAM, `esp_random()` hardware-RNG seeding, no-op lock/unlock (ESP32 has no swap to protect against), and only when building under the Arduino framework a `Serial`-based masked input and print path.
- **Arduino Uno / AVR is not supported.** 2KB of total SRAM, no OS, and no virtual memory make the dynamic-allocation, variable-length secure-string design in this library the wrong shape for that hardware. See the note at the top of `ShadowMem_esp32.h`.

Each platform header pulls in `ShadowMem_core.h` itself application code only ever includes the one platform header it needs, never the core header directly.

### Include-order requirement (desktop, glibc/Linux only)

`explicit_bzero`'s prototype is gated behind a glibc feature-test macro that must be set before the *first* system header is included anywhere in your translation unit not just before `ShadowMem_desktop.h`'s own includes. Concretely: include `ShadowMem_desktop.h` before `<string.h>` (or anything that pulls it in) in your `.c` file, or `#define _GNU_SOURCE` yourself as the very first line. If neither is done, the library still works correctly it falls back to a portable volatile-loop wipe automatically you just lose the stronger glibc primitive silently. See the comment at the top of `ShadowMem_desktop.h` for the underlying reason.

---

## Features

- **In-Memory Obfuscation:** Strings are XORed with a randomized, per-instance multi-byte key (32 bytes, cycled) rather than stored as plaintext. The key is allocated separately from the ciphertext buffer, not embedded in the same struct.
- **Secure Memory Wiping:** Buffers are overwritten with zeros using a platform-appropriate guaranteed-not-optimized-away primitive (`explicit_bzero` / `SecureZeroMemory` / `memset_s`, with a volatile-loop fallback) on free or cleanup.
- **Swap Protection (best-effort):** Attempts `mlock` (POSIX) / `VirtualLock` (Windows) on secret buffers so they're less likely to be paged to disk. This can silently fail without elevated privileges it is not guaranteed.
- **RAII-Style Automatic Cleanup (GCC/Clang):** Leverages `__attribute__((cleanup))` to guarantee automatic zeroing and deallocation when a secure string goes out of scope.
- **Explicit-Length API:** No function relies on NUL-termination. Every accessor takes or returns an explicit byte length, avoiding out-of-bounds reads on non-NUL-terminated secrets.
- **Constant-time-ish Comparison:** `shadowmem_string_equals` compares a secret's plaintext against a caller buffer without a third plaintext copy and without `strcmp`.
- **Secure Runtime Input:** Cross-platform masked input (`shadowmem_input`) with backspace handling, dynamic growth, and explicit EOF/Ctrl-D handling. Growth failures are reported via an output flag rather than silently truncating the secret.
- **Cross-Platform:** POSIX (Linux/macOS) and Windows, no external dependencies.
- **Header-Only:** Drop `ShadowMem.h` into any C99+ project.

---

## Threat Model & Honest Limitations

- XOR even multi-byte, even with a separately-allocated key is **not encryption**. Anyone with read access to process memory can recover the key and the plaintext; this only defeats a casual `strings`/pattern scan of a memory or core dump, not a deliberate memory-scraping attacker.
- Compiled binaries still expose any **hardcoded** string literals via `strings` at the executable level that's a separate problem from runtime memory hygiene. If you need to hide literals baked into the binary itself, use a dedicated obfuscator such as [Andrew Kelley's / adamyaxley's `Obfuscate`](https://github.com/adamyaxley/Obfuscate), not this library.
- `mlock`/`VirtualLock` are best-effort and commonly fail without elevated privileges (e.g. inside containers, or against `RLIMIT_MEMLOCK`). Check `ShadowMem_String.locked` if you need to know whether it actually succeeded but a `1` only means the call was attempted, not that the OS guaranteed protection.
- Secure zeroing prevents data from lingering in *freed* memory, but does nothing about copies the OS or hardware may have already made (swap taken before `mlock` succeeded, hibernation files, core dumps taken mid-decrypt, debugger attachment while the buffer is in its decrypted state via `decrypt_temp`/`print`).
- If you need real protection against a memory-scraping adversary, use an OS-backed secret store (Keychain, DPAPI, TPM-backed storage) or a maintained guarded-heap allocator such as libsodium's `sodium_malloc`/`sodium_mlock`, not hand-rolled XOR.

---

## API Reference

### Data Structures

- **`ShadowMem_String`**: `{ unsigned char* buffer; size_t size; size_t capacity; unsigned char* key; int locked; }` the obfuscated buffer, its true length, allocated capacity, a separately-allocated key, and whether memory locking was attempted successfully.

### Core Functions & Macros

- `ShadowMem_String shadowmem_string_from_raw(const char* raw, size_t len)` Obfuscates and stores raw plaintext bytes into a secure container. Returns a zeroed/empty container (`buffer == NULL`) on allocation failure or if `raw == NULL` with `len > 0`; **callers must check `.buffer != NULL`** before use.
- `void shadowmem_string_free(ShadowMem_String* s)` Securely wipes and frees the buffer and the key, and unlocks any locked pages.
- `void shadowmem_string_print(ShadowMem_String* s)` Temporarily decrypts, writes the exact byte length to `stdout` (no NUL-termination assumed), and re-encrypts.
- `unsigned char* shadowmem_string_decrypt_temp(ShadowMem_String* s, size_t* out_len)` Temporarily decrypts the buffer in place and returns a pointer plus its exact length via `out_len`. **The returned pointer is only valid until the next call to `shadowmem_string_encrypt_temp`** after that it points at ciphertext again. Do not treat it as a C string (no guaranteed trailing NUL).
- `void shadowmem_string_encrypt_temp(ShadowMem_String* s)` Re-encrypts the buffer after temporary access. Invalidates any pointer previously returned by `decrypt_temp`.
- `int shadowmem_string_equals(ShadowMem_String* s, const char* other, size_t other_len)` Compares the secret's plaintext against `other` without leaving a separate decrypted copy around; returns nonzero on match.
- `ShadowMem_String shadowmem_input(int mask, int* out_truncated)` Captures secure user input from the console (`mask = 1` for asterisk echoing, `0` for fully hidden). Handles EOF/Ctrl-D by stopping cleanly. If `out_truncated` is non-NULL, it's set to `1` when a reallocation failure cut input short (rather than silently truncating without telling the caller).
- `SM_SECURE` Macro enabling automatic scope-based cleanup on GCC and Clang. Gated on `defined(__GNUC__) || defined(__clang__)`.

---

## Quick Start Guide

### Example Usage

```c
/* Include the platform header first see the include-order note above. */
#include "ShadowMem_desktop.h"   /* or ShadowMem_esp32.h on ESP32 */
#include <stdio.h>
#include <string.h>

int main(void) {
    // 1. Create a secure string from raw input
    const char* secret = "SuperSecretPassword123";
    ShadowMem_String secure_str = shadowmem_string_from_raw(secret, strlen(secret));
    if (!secure_str.buffer) {
        fprintf(stderr, "Failed to allocate secure string\n");
        return 1;
    }

    // 2. Print safely without exposing the raw buffer permanently
    printf("Secure string (decrypted for display): ");
    shadowmem_string_print(&secure_str);
    printf("\n");

    // 3. Compare against a candidate without manual decrypt/encrypt bookkeeping
    if (shadowmem_string_equals(&secure_str, "wrong-guess", strlen("wrong-guess"))) {
        printf("Matched (unexpected)\n");
    } else {
        printf("Did not match (expected)\n");
    }

    // 4. Secure automatic cleanup using RAII (GCC/Clang)
#if SHADOWMEM_HAVE_CLEANUP
    {
        int truncated = 0;
        SM_SECURE ShadowMem_String pass = shadowmem_input(1, &truncated); // Masked input
        if (truncated) {
            fprintf(stderr, "Warning: input may have been truncated due to low memory\n");
        }
        printf("Password captured securely.\n");
    } // Automatically wiped and freed here!
#endif

    // 5. Manual cleanup
    shadowmem_string_free(&secure_str);
    return 0;
}
```

---

## Building and Running Tests (desktop)

```bash
gcc test_shadowmem.c -o test_shadowmem -std=c99 -Wall -Wextra
./test_shadowmem
```

Verified clean (no warnings, all checks passing) under both `-std=c99` and `-std=gnu11`, with `-Wall -Wextra -Wpedantic`.

The bundled test suite checks allocation success/failure paths, the empty-string edge case, `NULL`-raw handling, `shadowmem_string_equals` against both matching and mismatched inputs, and that the buffer's ciphertext actually differs from plaintext while encrypted. It does not (yet) include an automated harness for the interactive `shadowmem_input` path, since that requires a tty/pipe simulation. There is currently no automated test harness for the ESP32 platform header it has been reviewed for correctness but not compiled or run on hardware or in a simulator; treat it as less battle-tested than the desktop path until you've verified it on your target board.

---

## Why ShadowMem?

While exploring existing secure memory concepts in C, many available implementations suffered from portability issues, lack of GCC/Clang support, and insufficient maintenance for supply-chain or production environments.

ShadowMem was created as a clean-room, header-only library aimed at reasonable in-memory hygiene obfuscation-at-rest, guaranteed-where-possible secure zeroing, best-effort swap protection, and RAII cleanup for C99+ projects without external dependencies or compilation hurdles. The shared-core/platform-header split exists so the same hygiene logic (buffer bookkeeping, XOR toggling, construction/destruction) is written once and reused across desktop and embedded targets, rather than duplicated and potentially drifting between an original PC-oriented header and a copy-pasted embedded variant. It intentionally does not claim to be cryptography; see [Threat Model](#threat-model--honest-limitations) above.

## Note

**THIS IS NOT A SILVER BULLET.**

If you compile this with a hardcoded string literal, that literal is still visible via `strings` on the compiled binary this library operates at the *memory* level, not the *executable* level, and those are different problems. If you need to obfuscate literals baked into the binary itself, use a dedicated tool such as:

- <https://github.com/adamyaxley/Obfuscate/blob/master/obfuscate.h>

I do not hold any liability for use of this library, for AI-assisted misuse or misunderstanding of what it does, or for credentials leaked due to negligence.
