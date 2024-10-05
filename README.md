# cjks
I thought it would be funny to decrypt java spring cloud configs in c

## parse
```
FILE* fp = fopen("path/to/keystore", "rb");
cjks_io* io = cjks_io_fs_new(fp);
cjks* jks = cjks_parse_ex(io, "changeit", sizeof("changeit") - 1, "US-ASCII");
```

## get
```
cjks* pk = cjks_get(jks, "mytestkey");
assert(pk->tag == CJKS_PRIVATE_KEY_TAG);

cjks* ca = cjks_get(jks, "cert");
assert(ca->tag == CJKS_TRUSTED_CERT_TAG);
```

## evp
```
cjks* pk = cjks_get(jks, "mytestkey");
assert(pk->tag == CJKS_PRIVATE_KEY_TAG);

char encrypted_config[] = "some config";
size_t len_of_config;

EVP_PKEY* pk = cjks_2evp(mk->entry.pk);
int i = cjks_spring_decrypt(pk, encrypted_config, len_of_config);

printf("Decrypted config %.*s\n", i, encrypted_config);
```