#include <stdio.h>
#include "ShadowMem.h"

int main() {
    printf("=== ShadowMem C Test ===\n");

    // Test secure string creation and manual encryption/decryption
    const char* secret_text = "HelloShadowMemC";
    ShadowMem_String secure_str = shadowmem_string_from_raw(secret_text, strlen(secret_text));

    printf("Encrypted state (buffer is not plaintext): size = %zu\n", secure_str.size);

    printf("Decrypted via print function: ");
    shadowmem_string_print(&secure_str);
    printf("\n");

    // Test temporary decryption
    char* decrypted = shadowmem_string_decrypt_temp(&secure_str);
    printf("Decrypted temp pointer verification: matches original? %s\n", (strcmp(decrypted, secret_text) == 0 ? "YES" : "NO"));
    shadowmem_string_encrypt_temp(&secure_str); // Re-encrypt

    // Free securely
    shadowmem_string_free(&secure_str);
    printf("Secure string freed and wiped successfully.\n");

    // Test RAII cleanup attribute if supported
#if defined(__GNUC__) || defined(__CLANG__)
    {
        SM_SECURE ShadowMem_String raii_str = shadowmem_string_from_raw("RAII_Test", 9);
        printf("RAII string active, printing: ");
        shadowmem_string_print(&raii_str);
        printf("\n");
        // raii_str will be automatically wiped and freed when exiting this block!
    }
    printf("RAII block exited cleanly.\n");
#endif

    printf("All ShadowMem C tests completed successfully!\n");
    return 0;
}
