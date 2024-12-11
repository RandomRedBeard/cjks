
#include <cjks/cjks.h>
#include "test_base.h"

const unsigned char b64password[] = "AGMAaABhAG4AZwBlAGkAdA==";

void test_decrpyt_dig() {
    cjks_buf b64data = CJKS_BUF_INIT;
    cjks_read_from_res("/dig", &b64data);

    unsigned char data[2024];
    int dlen = cjks_b64decode(data, b64data.buf, b64data.len);

    char password[128];
    int plen = cjks_b64decode((unsigned char*)password, b64password, sizeof(b64password) - 1);

    unsigned char dest[2048], b64dest[4096];

    int r = cjks_sun_jks_decrypt(data, dest, dlen, password, plen);
    cjks_b64encode(b64dest, dest, dlen - 40);

    cjks_buf_clear(&b64data);
    cjks_read_from_res("/d.key", &b64data);

    assert(memcmp(b64data.buf, b64dest, b64data.len) == 0);

    cjks_buf_clear(&b64data);

}

void test_encrypt_dig() {
    const unsigned char b64iv[] = "24Zy9qgZlnJBNMMDpOEXDIEBJas=";

    unsigned char iv[SHA_DIGEST_LENGTH];
    cjks_b64decode(iv, b64iv, sizeof(b64iv) - 1);

    char password[128];
    int plen = cjks_b64decode((unsigned char*)password, b64password, sizeof(b64password) - 1);

    cjks_buf b64data = CJKS_BUF_INIT;
    cjks_read_from_res("/d.key", &b64data);

    unsigned char data[2024];
    int dlen = cjks_b64decode(data, b64data.buf, b64data.len);

    unsigned char dest[2048], fdest[4096], b64fdest[4096];
    memcpy(fdest, iv, SHA_DIGEST_LENGTH);

    cjks_sun_jks_crypt(data, dest, dlen, iv, password, plen);

    memcpy(fdest + SHA_DIGEST_LENGTH, dest, dlen);
    cjks_sha1(fdest + SHA_DIGEST_LENGTH + dlen, 2, password, (size_t)plen, data, (size_t)dlen);

    int b64len = cjks_b64encode(b64fdest, fdest, SHA_DIGEST_LENGTH + dlen + SHA_DIGEST_LENGTH);

    cjks_buf_clear(&b64data);
    cjks_read_from_res("/dig", &b64data);

    assert(b64data.len == b64len);

    assert(memcmp(b64fdest, b64data.buf, b64data.len) == 0);

    cjks_buf_clear(&b64data);

    // Write x509_sig object

    ASN1_OCTET_STRING* pdigest;
    X509_ALGOR* palg;
    X509_SIG* sig = X509_SIG_new();
    X509_SIG_getm(sig, &palg, &pdigest);

    ASN1_OBJECT* obj = OBJ_txt2obj("1.3.6.1.4.1.42.2.17.1.1", 1);
    assert(obj);
    int i = X509_ALGOR_set0(palg, obj, V_ASN1_NULL, NULL);

    ASN1_OCTET_STRING_set(pdigest, fdest, SHA_DIGEST_LENGTH + dlen + SHA_DIGEST_LENGTH);

    unsigned char sigbufdump[4096], * sigbufptr = sigbufdump;
    i2d_X509_SIG(sig, &sigbufptr);

    unsigned char b64sigbuf[4096];
    i = cjks_b64encode(b64sigbuf, sigbufdump, sigbufptr - sigbufdump);

    unsigned char sbug[] = "MIIE/TAOBgorBgEEASoCEQEBBQAEggTp24Zy9qgZlnJBNMMDpOEXDIEBJasI//CuEcarUAGv5+FtPBRsAS+zfDR7J9nGxTNo3h1BH64GbkDgxmKU4Xc0vlzEoXiOXpCX+jf9xKpSzHpZjnLvGIsziNvl4J8b9TsPWDDahdINXB0H4/S64+pU2Zy+pPanS9dG9G8HYIYUixCIQxPJXQO+H2Brg0kCuQ9PAXmtT6Dia5qZKq2EZ+5Gz9IKNi3Beaq2CsDoEaGa/8/lBtwBtdYX1apTBs73K0Y9ClYjUuju2j/sYGNRCPGUlYyNQNJh7iuPZvPBnnOx5YWPSLMX1kg/bK2uwHwQzEDvkf2BFpZk85rgMLEhRvDPRe67iih4qnJ6dn5rXCSyOa7KdofswZaFqffgfL/P7E/1DhSzFuW7DaEtiIwgFRIQ8gHrOeOMLjCsFY8f0VI8hGyCFRnjwI3dBalRdRP5OzbaZzE8/Pz1RkEXgrqVGExuPOiyLbd0WCRS7ZvjbC6p0Jh0CVynXnH07rnWP+um4Weg4dd4mrcOVAPrQCNBQuB9mhQUHEn3li6MOjiA5CeJw/Ez/qaopSBc6eTlJlyzKiqCkS/QIv18OhPfjBwDZXayHDh12JSem0jsyuqpryCTVZFyrAaXoXubuLf1AGKEGsRR+1vjL9YwjVXx1NoFDfHUujIQePRbZz61ufmsAUlTRepRy90TmpDvukND6qFoZi0mvHpW0ZXmclaShTXm2aLJJIBCGOkUmTgW9dzIx83eiJUoQODuxNtOlBcT0GC4IbAf84ky2ATW9zXK59ePKRs39B2Ly/jg/M1/zAMSoME7CQl2oV0TAdHjmW1a6qk9nJ4qjehJ6aIQ52mQ43NpNxQMVNAsALF6gBu0JCZYC+y/5avXVjnAaec85LtwFRv61fBUhIbJLm+Ru3SOU8oUUitjYhRGtZlp9TheXAYn87MjV348Po5O/Fj12ID4/2w+z6Y0iscX0c9FNl/irWNPEUP2E3mXmdmMseIO9lChjfaDojmNcmL9OylgzSw9zAXwCs/U94Tsm0aynQ9AY9+XrG/zqJmeyxr14E1d3Wi0lleVM9ZozBNQu5Zdi0t80+qHpD9KXuqKwDNKobyjhGtReE/1fHxH05xx+5IJsKWnOg9gd/qU0eiJTPQ74gjoNo4iNS10HJM9LnvL7395S0jUNWHJSRpzCoFEDDPCx2ldlrWm9gJwAOriHCPbXVSIrqiJeFP5/X73566NtZvuCjG4Hpbl1RWA7qrUNR6hXu2NsoVyUozjDuRaJaCyBkNiJmHggSnumZnWIum7K4tmDFtBX4Pa1Ip0tHyysGE4HY/8ooEC4OXQRX2/ryiIilpzaP7QiF3dazx0PCSZcYqTcKvcESeiih3REy0GGIpu1orpJucwsgf5w8Om0vD0RLiBT2WBUCHU6h6ilvRF6Hj3KRWqyqtORw4m7HyyQLZhFjoRR/QU7xmIiA2UcFT/yobk1uUQ1gxzUJlMovzVn+FYAUI8ahjF//2XE4kOioO7pBwPK8AQRgYXvwfJB/muTtAfe2myLTtFbShs5erctBfZmORvgxOYv+QE4ZfU/tLUSm2JZPsJ9MHbH2+KO9DmrDbmCnIim+vQmwZnnT4DEYO9BY7G9K+j+jtKu2siRhLq+NB8Q8repVRIlZsQkmQIno6R1cxjKFUfI2PVZSH+TPHX";

    assert(memcmp(b64sigbuf, sbug, i) == 0);
    
}

test_st tests[] = {
    {"decrypt_dig", test_decrpyt_dig},
    {"encrypt_dig", test_encrypt_dig},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}