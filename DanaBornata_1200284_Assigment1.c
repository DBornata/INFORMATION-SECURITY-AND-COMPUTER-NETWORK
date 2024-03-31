#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#define max_word_length 16

// Function to Decrypt the Ciphertext using the key and IV
int Decrypt(unsigned char *Ciphertext, int Ciphertext_Length, unsigned char *K,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *C;
// the length of the decrypted plaintext and the length of each block

    int Length;
    int plaintext_Length;
// If the creation fails, return -1 to indicate an error
    if (!(C = EVP_CIPHER_CTX_new())) return -1;

// Initialize the decryption operation with the provided key, IV, and cipher algorithm

    if (1 != EVP_DecryptInit_ex(C, EVP_aes_128_cbc(), NULL, K, iv))
        return -1;

// Perform the decryption operation for the given ciphertext and Store the decrypted plaintext in the 'plaintext' buffer
//then Update the 'Length' variable with the length of the decrypted plaintext

    if (1 != EVP_DecryptUpdate(C, plaintext, &Length, Ciphertext, Ciphertext_Length))
        return -1;// If the decryption update operation fails, return -1 to indicate an error
    plaintext_Length = Length;


    if (1 != EVP_DecryptFinal_ex(C, plaintext + Length, &Length)) return -1;// If the finalization fails, return -1 to indicate an error
    plaintext_Length += Length;// Update the total length of the decrypted plaintext by adding the length of the final block



    EVP_CIPHER_CTX_free(C);

    return plaintext_Length;//Return the total length of the decrypted plaintext

}

int main() {
    // Initialize Ciphertext, plaintext, and IV
    unsigned char Ciphertext[] = {
        0x60, 0x29, 0xc2, 0x2a, 0x7b, 0x6c, 0x95, 0x85, 0x2d, 0x20, 0x53, 0x10,
        0x4b, 0x65, 0x43, 0x3f, 0xd6, 0xc3, 0x9c, 0x1f, 0xda, 0x0d, 0x65, 0x64,
        0xe5, 0x94, 0x14, 0xfd, 0x82, 0xdc, 0x01, 0xa7
    };
    unsigned char plaintext[] = "This is a top secret.";
    unsigned char iv[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // Open the dictionary file
    FILE *file = fopen("words.txt", "r");
    if (file == NULL) {
        perror("There was an error opening the file. Make sure the file is correct\n");
        return 1;
    }

    // Iterate through each word in the dictionary
    char word[max_word_length + 1]; // +1 for null terminator
    while (fscanf(file, "%s", word) == 1) {
        // Ensure the word is not longer than MAX_WORD_LENGTH
        if (strlen(word) > max_word_length) continue;

        // Append pound signs to the word to form a 128-bit key
        strcat(word, "################");
        word[16] = '\0';  // Ensure the key length is 16 bytes

        // Attempting key
        printf("Try checking the key: %s\n", word);

        // Decrypt using the current key
        int plaintext_Length = Decrypt(Ciphertext, sizeof(Ciphertext), (unsigned char *)word, iv, plaintext);

	
        // Check if the Decrypted plaintext matches the expected plaintext
        if (plaintext_Length > 0 && memcmp(plaintext, "This is a top secret.", 21) == 0) {
            // Output the key to key.txt
            FILE *key_file = fopen("key.txt", "w");
            if (key_file == NULL) {
                perror("Error creating key file");
                fclose(file);
                return 1;
            }
            fprintf(key_file, "%s", word);
            fclose(key_file);
            char *finalkey = strtok(word, "#");
            printf("\n\n **********The Key was found successfully*****************:key:%s\n", finalkey);
            fclose(file);

            return 0;
        }
    }

    printf("sorry the Key not found in the file words.\n");
    fclose(file);
    return 0;
}
