// just text xor encrypt
// :0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* XORCipher(char* data, char* key, int datalen, int keylen) {
    
    char* output = (char*)malloc(sizeof(char) * datalen + 1);

    if(output == NULL) return NULL;

    for(int i = 0; i < datalen; i++) output[i] = data[i] ^ key[i % keylen];

    output[datalen] = '\0';

    return output;

}

void print_hex(const char* data, int len) {

    for(int i = 0; i < len; i++) printf("%02x", (unsigned char)data[i]);

    printf("\n");

}

void xor_encrypt_text(char* text, char* key) {

    int datalen = strlen(key);
    int keylen = strlen(key);

    if(datalen == 0 || keylen == 0) {

        printf("text or key cannot be empty\n");
        return;

    }

    char* cipherText = XORCipher(text, key, datalen, keylen);

    printf("encrypt message(hex): ");
    print_hex(cipherText, datalen);

    char* plaintext = XORCipher(cipherText, key, datalen, keylen);

    printf("decrypted message(string): %s\n", plaintext);

    // free memory 
    free(cipherText);
    free(plaintext);
}

// main test xor 
int main(void) {
    
    char text[256];
    char key[256];
    
    printf("> select text for encrypt: ");

    fgets(text, sizeof(text), stdin);
    text[strcspn(text, "\n")] = 0;

    printf("> okay, then select key for xor: ");

    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = 0;

    printf("your parametrs(text: %s, key: %s)\n", text, key);


    xor_encrypt_text(text, key);
}