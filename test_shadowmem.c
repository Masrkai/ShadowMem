/* ShadowMem_desktop.h must be included first (or _GNU_SOURCE defined
 * first) on glibc/Linux so explicit_bzero's prototype is visible in
 * this translation unit — see the note at the top of that header. */


#include "ShadowMem_desktop.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } \
    else { printf("OK:   %s\n", msg); } \
} while (0)

int main(void) {
    printf("=== ShadowMem C Test (fixed) ===\n");

    /* 1. Basic round trip, using explicit-length compare (no strcmp OOB risk) */
    const char* secret_text = "HelloShadowMemC";
    size_t secret_len = strlen(secret_text);
    ShadowMem_String s1 = shadowmem_string_from_raw(secret_text, secret_len);
    CHECK(s1.buffer != NULL, "allocation succeeded");
    CHECK(s1.size == secret_len, "size matches input length");

    /* Confirm the buffer is NOT plaintext while "encrypted" (the original
     * test never checked this at all). */
    CHECK(memcmp(s1.buffer, secret_text, secret_len) != 0,
          "buffer differs from plaintext while encrypted");

    CHECK(shadowmem_string_equals(&s1, secret_text, secret_len),
          "decrypted content matches original (constant-time compare)");

    /* 2. decrypt_temp / encrypt_temp round trip with explicit length,
     *    no reliance on NUL termination. */
    size_t plen = 0;
    unsigned char* p = shadowmem_string_decrypt_temp(&s1, &plen);
    CHECK(p != NULL && plen == secret_len, "decrypt_temp returns correct length");
    CHECK(memcmp(p, secret_text, secret_len) == 0, "decrypt_temp content correct");
    shadowmem_string_encrypt_temp(&s1);
    CHECK(memcmp(s1.buffer, secret_text, secret_len) != 0,
          "buffer re-encrypted after encrypt_temp (dangling-pointer footgun avoided)");

    shadowmem_string_free(&s1);
    CHECK(s1.buffer == NULL && s1.key == NULL, "free() clears pointers");

    /* 3. Empty string edge case (len == 0) */
    ShadowMem_String s2 = shadowmem_string_from_raw("", 0);
    CHECK(s2.buffer != NULL, "empty string still allocates (capacity=1)");
    CHECK(s2.size == 0, "empty string has size 0");
    CHECK(shadowmem_string_equals(&s2, "", 0), "empty string equals empty compare");
    shadowmem_string_free(&s2);

    /* 4. NULL raw with nonzero len -> fails safe, doesn't crash/UB */
    ShadowMem_String s3 = shadowmem_string_from_raw(NULL, 5);
    CHECK(s3.buffer == NULL && s3.size == 0, "NULL raw with len>0 fails safe");
    shadowmem_string_free(&s3); /* must be safe to call on empty struct */

    /* 5. Mismatched-length compare doesn't false-positive */
    ShadowMem_String s4 = shadowmem_string_from_raw("abc", 3);
    CHECK(!shadowmem_string_equals(&s4, "abcd", 4), "different length correctly not equal");
    CHECK(!shadowmem_string_equals(&s4, "abd", 3), "same length, different content not equal");
    shadowmem_string_free(&s4);

    /* 6. RAII cleanup path — now correctly gated on __clang__ too */
#if SHADOWMEM_HAVE_CLEANUP
    {
        SM_SECURE ShadowMem_String raii_str = shadowmem_string_from_raw("RAII_Test", 9);
        CHECK(shadowmem_string_equals(&raii_str, "RAII_Test", 9), "RAII string readable before scope exit");
        printf("(raii_str will be wiped automatically at scope exit)\n");
    }
    printf("RAII block exited cleanly.\n");
#else
    printf("Cleanup attribute not supported on this compiler; skipping RAII test.\n");
#endif

    /* 7. shadowmem_input is interactive (stdin) so not exercised in this
     *    automated test, but its signature now surfaces truncation via
     *    out_truncated rather than silently dropping data. Documented here
     *    rather than tested, since it requires a tty/pipe harness. */

    printf("\n%d check(s) failed.\n", failures);
    printf(failures == 0 ? "All ShadowMem C tests completed successfully!\n"
                          : "SOME TESTS FAILED.\n");
    return failures == 0 ? 0 : 1;
}
