#include <oqs/oqs.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

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
    uint8_t ciphertext[OQS_KEM_frodokem_640_aes_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_frodokem_640_aes_length_shared_secret];
    OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);

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
    
    // Check if the plaintext is within the acceptable length

    // TODO: Choose a symmetric cipher and implement encryption using shared_secret

    // 4. Decryption
    uint8_t shared_secret_d[OQS_KEM_frodokem_640_aes_length_shared_secret];
    if (OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Decapsulation failed\n");
        return 1;
    }

    // Print decrypted shared secret for decryption
    printf("Shared Secret (Decryption):\n");
    for (size_t i = 0; i < sizeof(shared_secret_d); i++) {
        printf("%02x", shared_secret_d[i]);
    }
    printf("\n");

    // 5. Ciphertext Decryption
    // TODO: Implement decryption using decapsulated_shared_secret

    // 6. Memory Cleanup
    OQS_KEM_free(kem);

    return 0;
}
