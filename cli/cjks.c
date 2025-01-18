#include <time.h>
#include <cjks/cjks.h>
#include <openssl/x509.h>
#include "private/debug.h"

void print_ca(cjks_ca* ca) {
    printf("%d\n", ca->n);
    const uchar* b = ca->cert.buf;
    X509* x = d2i_X509(NULL, &b, ca->cert.len);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME* issuer = X509_get_issuer_name(x);
    X509_NAME_print_ex_fp(stdout, name, 0, 0);
    puts("");
    X509_NAME_print_ex_fp(stdout, issuer, 0, 0);
    puts("");

    X509_free(x);
}

void print_pk(cjks_pkey* pk) {
    printf("klen: %zu\n", pk->key.len);
    cjks_ca* ca = pk->cert_chain;
    while (ca) {
        print_ca(ca);
        ca = ca->next;
    }
}

void print_jks(cjks* jks) {
    while (jks) {
        printf("%u: %s - %d - %llu\n", jks->n, jks->alias, jks->tag, jks->ts);
        if (jks->tag == CJKS_PRIVATE_KEY_TAG) {
            print_pk(jks->pk);
        }
        else {
            print_ca(jks->ca);
        }

        puts("");
        jks = jks->next;
    }
}

typedef struct arg_st {
    const char* lname;
    const char* sname;
    const char* desc;
    void* v;
    uint8 offset;
    int flags;
} arg_t;

#define ARG_FLAG (1 << 0)
#define ARG_COMMAND (1 << 1)
#define ARG_OPTIONAL (1 << 7);

arg_t* find_arg(arg_t* args, const char* name) {
    size_t namel = strlen(name);
    while (args->sname || args->lname) {
        if (args->sname && strncmp(name, args->sname, namel) == 0) {
            return args;
        }

        if (args->lname && strncmp(name, args->lname, namel) == 0) {
            return args;
        }
        args++;
    }

    return NULL;
}

void print_help(arg_t* args) {
    printf("cjkstool: 1.0\n");
    printf("%s%-10s\n", "Argument", "Description");
    while (args->sname || args->lname) {
        if (args->sname && args->lname)
            printf("%s,%s\t%s\n", args->sname, args->lname, args->desc);
        else if (args->sname)
            printf("%s\t%s\n", args->sname, args->desc);
        else
            printf("%s\t%s\n", args->lname, args->desc);

        args++;
    }
}

struct tool_st {
    const char* ifile;
    uint8 verbose;
    const char* cmd;
};

void print_tool(struct tool_st* tool) {
    printf("File %s\n", tool->ifile);
    printf("Verbose %d\n", tool->verbose);
    printf("Command: %s\n", tool->cmd);
}

int main(int argc, char** argv) {
    struct tool_st tool = {
        NULL, 0, NULL
    };

    arg_t args[] = {
        {
            "--input", "-i", "Input file", &tool, offsetof(struct tool_st, ifile), 0
        },
        {
            NULL, "-v", "Verbose", &tool, offsetof(struct tool_st, verbose), ARG_FLAG
        },
        {
            "parse", NULL, "Parse keystore", &tool, offsetof(struct tool_st, cmd), ARG_COMMAND | ARG_FLAG
        },
        {NULL, NULL, NULL, NULL, 0}
    };

    print_help(args);

    arg_t* sargs = NULL;

    char* aptr = NULL, * vptr = NULL;
    for (int i = 0; i < argc; i++) {
        aptr = *(argv + i);

        sargs = find_arg(args, aptr);
        if (!sargs) {
            printf("Unknown arg: %s\n", aptr);
            continue;
        }
        if (!(ARG_FLAG & sargs->flags)) {
            if (i + 1 == argc) {
                perror("Expected value");
                continue;
            }
            i++;
            vptr = *(argv + i);
            if (*vptr == '-') {
                perror("Bad arg");
                continue;
            }
            *(char**)((char*)sargs->v + sargs->offset) = vptr;
        } 
        else if (ARG_COMMAND & sargs->flags) {
            *(char**)((char*)sargs->v + sargs->offset) = aptr;
        }
        else {
            *((char*)sargs->v + sargs->offset) = 1;
        }

    }

    print_tool(&tool);

    return 0;
}

// int main(int argc, char** argv) {
//     time_t tm = time(0);
//     cjks* jks = cjks_parse_ex2(argv[1], "changeit", sizeof("changeit") - 1, "US-ASCII");
//     print_jks(jks);
//     cjks_free(jks);
//     printf("%ld\n", time(0) - tm);

//     return 0;
// }