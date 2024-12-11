#include "test_base.h"

#include <stddef.h>
#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ossl_typ.h>

#include <cjks/cjks.h>

// typedef struct epkey_info_st {
//     X509_ALGOR *algo;
//     ASN1_OCTET_STRING *edata;
// } epkey_info;

// ASN1_SEQUENCE(epkey_info) = {
//     ASN1_SIMPLE(epkey_info, algo, X509_ALGOR),
//     ASN1_SIMPLE(epkey_info, edata, ASN1_OCTET_STRING),
// } ASN1_SEQUENCE_END(epkey_info)

int main() {
    unsigned char data[] = "MIIE/TAOBgorBgEEASoCEQEBBQAEggTp24Zy9qgZlnJBNMMDpOEXDIEBJasI//CuEcarUAGv5+FtPBRsAS+zfDR7J9nGxTNo3h1BH64GbkDgxmKU4Xc0vlzEoXiOXpCX+jf9xKpSzHpZjnLvGIsziNvl4J8b9TsPWDDahdINXB0H4/S64+pU2Zy+pPanS9dG9G8HYIYUixCIQxPJXQO+H2Brg0kCuQ9PAXmtT6Dia5qZKq2EZ+5Gz9IKNi3Beaq2CsDoEaGa/8/lBtwBtdYX1apTBs73K0Y9ClYjUuju2j/sYGNRCPGUlYyNQNJh7iuPZvPBnnOx5YWPSLMX1kg/bK2uwHwQzEDvkf2BFpZk85rgMLEhRvDPRe67iih4qnJ6dn5rXCSyOa7KdofswZaFqffgfL/P7E/1DhSzFuW7DaEtiIwgFRIQ8gHrOeOMLjCsFY8f0VI8hGyCFRnjwI3dBalRdRP5OzbaZzE8/Pz1RkEXgrqVGExuPOiyLbd0WCRS7ZvjbC6p0Jh0CVynXnH07rnWP+um4Weg4dd4mrcOVAPrQCNBQuB9mhQUHEn3li6MOjiA5CeJw/Ez/qaopSBc6eTlJlyzKiqCkS/QIv18OhPfjBwDZXayHDh12JSem0jsyuqpryCTVZFyrAaXoXubuLf1AGKEGsRR+1vjL9YwjVXx1NoFDfHUujIQePRbZz61ufmsAUlTRepRy90TmpDvukND6qFoZi0mvHpW0ZXmclaShTXm2aLJJIBCGOkUmTgW9dzIx83eiJUoQODuxNtOlBcT0GC4IbAf84ky2ATW9zXK59ePKRs39B2Ly/jg/M1/zAMSoME7CQl2oV0TAdHjmW1a6qk9nJ4qjehJ6aIQ52mQ43NpNxQMVNAsALF6gBu0JCZYC+y/5avXVjnAaec85LtwFRv61fBUhIbJLm+Ru3SOU8oUUitjYhRGtZlp9TheXAYn87MjV348Po5O/Fj12ID4/2w+z6Y0iscX0c9FNl/irWNPEUP2E3mXmdmMseIO9lChjfaDojmNcmL9OylgzSw9zAXwCs/U94Tsm0aynQ9AY9+XrG/zqJmeyxr14E1d3Wi0lleVM9ZozBNQu5Zdi0t80+qHpD9KXuqKwDNKobyjhGtReE/1fHxH05xx+5IJsKWnOg9gd/qU0eiJTPQ74gjoNo4iNS10HJM9LnvL7395S0jUNWHJSRpzCoFEDDPCx2ldlrWm9gJwAOriHCPbXVSIrqiJeFP5/X73566NtZvuCjG4Hpbl1RWA7qrUNR6hXu2NsoVyUozjDuRaJaCyBkNiJmHggSnumZnWIum7K4tmDFtBX4Pa1Ip0tHyysGE4HY/8ooEC4OXQRX2/ryiIilpzaP7QiF3dazx0PCSZcYqTcKvcESeiih3REy0GGIpu1orpJucwsgf5w8Om0vD0RLiBT2WBUCHU6h6ilvRF6Hj3KRWqyqtORw4m7HyyQLZhFjoRR/QU7xmIiA2UcFT/yobk1uUQ1gxzUJlMovzVn+FYAUI8ahjF//2XE4kOioO7pBwPK8AQRgYXvwfJB/muTtAfe2myLTtFbShs5erctBfZmORvgxOYv+QE4ZfU/tLUSm2JZPsJ9MHbH2+KO9DmrDbmCnIim+vQmwZnnT4DEYO9BY7G9K+j+jtKu2siRhLq+NB8Q8repVRIlZsQkmQIno6R1cxjKFUfI2PVZSH+TPHX";

    unsigned char dest[2048], * dptr = dest;
    int dlen = cjks_b64decode(dest, data, sizeof(data) - 1);
    printf("%d\n", dlen);

    X509_SIG* sig = NULL;

    if (!ASN1_item_d2i((ASN1_VALUE**)&sig, (const unsigned char**)&dptr, dlen, ASN1_ITEM_rptr(X509_SIG))) {
        ERR_print_errors_fp(stderr);
        printf("Failed\n");
        return -1;
    }

    //ASN1_TYPE *type = NULL;
    /*while ((type = sk_ASN1_TYPE_pop(epkey->algo->parameters))) {
        printf("%d\n", type->type);
    }*/
    return 0;
}