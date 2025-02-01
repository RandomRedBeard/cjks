#include <openssl/pem.h>

#include <cjks/spring.h>
#include <cjks/cjks.h>


void spring_encrypt(EVP_PKEY* pk, const char* src, size_t len) {
    printf("%s - %d\n", src, len);
    int alsz = (((EVP_PKEY_get_size(pk) + 16 + 2 + len + 16) * 4) / 3) + 4;
    printf("%d %d\n", (len % 16), alsz);
    uchar* dst = malloc(alsz);
    int dlen = cjks_spring_encrypt(pk, src, len, dst);
    printf("%d - %.*s\n", dlen, dlen, dst);

    int slen = cjks_spring_decrypt(pk, dst, dlen, src);
    printf("%d - %.*s\n", slen, slen, src);
    free(dst);
}

int main(int argc, char** argv) {
    printf("%s - %s\n", *(argv + 1), *(argv + 2));
    FILE* fp = fopen(*(argv + 1), "rb");
    EVP_PKEY* pk = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    ERR_print_errors_fp(stdout);
    spring_encrypt(pk, *(argv + 2), strlen(*(argv + 2)));
    return 0;
}