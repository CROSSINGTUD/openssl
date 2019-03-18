#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/lhash.h>
#include <oqs/oqs.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#include <crypto/include/internal/evp_int.h>
#include <crypto/include/internal/asn1_int.h>

#endif

#define SECTION         "combine"

#define PROMPT          "prompt"
#define STRING_MASK     "string_mask"
#define UTF8_IN         "utf8"


int oqs_combine_keys(const EVP_PKEY *classical_key, const EVP_PKEY *oqs_keyp, const EVP_PKEY *result);
typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_PQKEY, OPT_CLASSKEY,
    OPT_CONFIG, OPT_KEYFORM, OPT_KEYOUT, OPT_PASSIN, OPT_PASSOUT,
} OPTION_CHOICE;

const OPTIONS combine_options[] = {
        {"help", OPT_HELP, '-', "Display this summary"},
        {"inform", OPT_INFORM, 'F', "Input format - DER or PEM"},
        {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
        {"pqkey", OPT_PQKEY, 's', "Private pqkey to use"},
        {"classkey", OPT_CLASSKEY, 's', "Private classical key to use"},
        {"keyform", OPT_KEYFORM, 'f', "Key file format"},
        {"config", OPT_CONFIG, '<', "Request template file"},
        {"keyout", OPT_KEYOUT, '>', "File to send the key to"},
        {"passin", OPT_PASSIN, 's', "Private key password source"},
        {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
        {NULL}
};




int combine_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pqpkey = NULL, *classpkey = NULL;
    char *pqkeyfile = NULL, *classkeyfile = NULL;
    char *prog;
    char *passin = NULL, *passout = NULL;
    char *nofree_passin = NULL, *nofree_passout = NULL;
    char *keyout = NULL;
    OPTION_CHOICE o;
    int ret = 1;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyform = FORMAT_PEM;



    prog = opt_init(argc, argv, combine_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
            case OPT_EOF:
            case OPT_ERR:
            opthelp:
                BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
                goto end;
            case OPT_HELP:
                opt_help(combine_options);
                ret = 0;
                goto end;
            case OPT_INFORM:
                if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                    goto opthelp;
                break;
            case OPT_OUTFORM:
                if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                    goto opthelp;
                break;
            case OPT_PQKEY:
                pqkeyfile = opt_arg();
                break;
            case OPT_CLASSKEY:
                classkeyfile = opt_arg();
                break;
            case OPT_KEYFORM:
                if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyform))
                    goto opthelp;
                break;
            case OPT_KEYOUT:
                keyout = opt_arg();
                break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (pqkeyfile != NULL) {
        pqpkey = load_key(pqkeyfile, keyform, 0, passin, e, "Private Key");
    }
    if (classkeyfile != NULL) {
        classpkey = load_key(classkeyfile, keyform, 0, passin, e, "Private Key");
    }
    EVP_PKEY *tmp = EVP_PKEY_new();
    oqs_combine_keys(classpkey,pqpkey,tmp);

    out = bio_open_owner(keyout, outformat, 1);

    PEM_write_bio_PrivateKey(out, tmp, NULL,NULL, 0, NULL, passout);

    ret = 0;
    end:
    if (ret) {
        ERR_print_errors(bio_err);
    }
    BIO_free(in);
    BIO_free_all(out);
    release_engine(e);
    if (passin != nofree_passin)
        OPENSSL_free(passin);
    if (passout != nofree_passout)
        OPENSSL_free(passout);
    return ret;
}