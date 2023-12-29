#include <oqs/oqs.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    // 1. Key Generation
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) {
        fprintf(stderr, "Error creating KEM instance\n");
        return 1;
    }

    uint8_t public_key[OQS_KEM_frodokem_640_aes_length_public_key];
    uint8_t secret_key[OQS_KEM_frodokem_640_aes_length_secret_key];
    OQS_KEM_keypair(kem, public_key, secret_key);

    // Print public and secret keys
    printf("Public Key:\n");
    for (size_t i = 0; i < sizeof(public_key); i++) {
        printf("%02x", public_key[i]);
    }
    printf("\n");

    printf("Secret Key:\n");
    for (size_t i = 0; i < sizeof(secret_key); i++) {
        printf("%02x", secret_key[i]);
    }
    printf("\n");

    // 2. Encryption
    const size_t iv_len = 12;  // AES-GCM IV length
    uint8_t iv[iv_len];
    if (RAND_bytes(iv, iv_len) != 1) {
        fprintf(stderr, "Error generating random IV\n");
        return 1;
    }

    uint8_t ciphertext[OQS_KEM_frodokem_640_aes_length_ciphertext + iv_len];
    uint8_t shared_secret_e[OQS_KEM_frodokem_640_aes_length_shared_secret];
    OQS_KEM_encaps(kem, ciphertext + iv_len, shared_secret_e, public_key);

    // Copy IV to the beginning of the ciphertext
    memcpy(ciphertext, iv, iv_len);

    // Print ciphertext and shared secret for encryption
    printf("Ciphertext:\n");
    for (size_t i = 0; i < sizeof(ciphertext); i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    printf("Shared Secret (Encryption):\n");
    for (size_t i = 0; i < sizeof(shared_secret_e); i++) {
        printf("%02x", shared_secret_e[i]);
    }
    printf("\n");

    // 3. Plaintext Encryption
    const char *plaintext = "This is the secret message.";

    // 4. Choose a symmetric cipher (AES-GCM) and implement encryption using shared_secret
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating EVP_CIPHER_CTX\n");
        return 1;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, shared_secret_e, iv) != 1) {
        fprintf(stderr, "Error initializing encryption\n");
        return 1;
    }

    // Allocate memory for ciphertext
    size_t max_ciphertext_len = strlen(plaintext) + EVP_CIPHER_block_size(cipher);
    uint8_t *encrypted_text = malloc(max_ciphertext_len);
    if (!encrypted_text) {
        fprintf(stderr, "Error allocating memory for encrypted text\n");
        return 1;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, encrypted_text, &len, (const uint8_t *)plaintext, strlen(plaintext)) != 1) {
        fprintf(stderr, "Error encrypting plaintext\n");
        return 1;
    }

    size_t encrypted_len = len;

    if (EVP_EncryptFinal_ex(ctx, encrypted_text + len, &len) != 1) {
        fprintf(stderr, "Error finalizing encryption\n");
        return 1;
    }

    encrypted_len += len;

    printf("Encrypted Text:\n");
    for (size_t i = 0; i < encrypted_len; i++) {
        printf("%02x", encrypted_text[i]);
    }
    printf("\n");

    // 5. Decryption
    uint8_t shared_secret_d[OQS_KEM_frodokem_640_aes_length_shared_secret];
    if (OQS_KEM_decaps(kem, shared_secret_d, ciphertext + iv_len, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Decapsulation failed\n");
        return 1;
    }

    // Extract IV from ciphertext
    memcpy(iv, ciphertext, iv_len);

    // 6. Ciphertext Decryption
    EVP_CIPHER_CTX *decrypt_ctx = EVP_CIPHER_CTX_new();
    if (!decrypt_ctx) {
        fprintf(stderr, "Error creating EVP_CIPHER_CTX for decryption\n");
        return 1;
    }

    if (EVP_DecryptInit_ex(decrypt_ctx, cipher, NULL, shared_secret_d, iv) != 1) {
        fprintf(stderr, "Error initializing decryption\n");
        return 1;
    }

    // Allocate memory for decrypted text
    uint8_t *decrypted_text = malloc(max_ciphertext_len + EVP_CIPHER_block_size(cipher));
    if (!decrypted_text) {
        fprintf(stderr, "Error allocating memory for decrypted text\n");
        return 1;
    }

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(decrypt_ctx, decrypted_text, &len, ciphertext + iv_len, encrypted_len) != 1) {
        fprintf(stderr, "Error decrypting ciphertext\n");
        return 1;
    }

    size_t decrypted_len = len;

    // Print debugging information after decrypting
    printf("IV used for decryption:\n");
    for (size_t i = 0; i < iv_len; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    printf("Decrypted Shared Secret (Before Decryption):\n");
    for (size_t i = 0; i < sizeof(shared_secret_d); i++) {
        printf("%02x", shared_secret_d[i]);
    }
    printf("\n");

    // Print decrypted text before finalizing decryption
    printf("Decrypted Text (Before Finalizing Decryption):\n");
    for (size_t i = 0; i < decrypted_len; i++) {
        printf("%c", decrypted_text[i]);
    }
    printf("\n");

    // Finalize decryption
    if (EVP_DecryptFinal_ex(decrypt_ctx, decrypted_text + len, &len) != 1) {
        fprintf(stderr, "Error finalizing decryption\n");
        return 1;
    }

    decrypted_len += len;

    printf("Decrypted Text: %.*s\n", (int)decrypted_len, decrypted_text);

    // 7. Memory Cleanup
    OQS_KEM_free(kem);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_CTX_free(decrypt_ctx);
    free(encrypted_text);
    free(decrypted_text);

    return 0;
}