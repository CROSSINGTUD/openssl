#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <apps/apps.h>
#include <string.h>

static void *v2i_HybridKey(const struct v3_ext_method *method,
                              struct v3_ext_ctx *ctx,
                              STACK_OF(CONF_VALUE) *values)
{
	X509_PUBKEY* ext = NULL;
	BIO *pubkey = NULL;
	EVP_PKEY *pkey = NULL;

	//we need exactly one value, specifying the public key file
	if (sk_CONF_VALUE_num(values) != 1) {
    	X509V3err(X509V3_F_V2I_HYBRIDKEY, X509V3_R_INVALID_OPTION);
		goto err;
	}

	CONF_VALUE *val = sk_CONF_VALUE_value(values, 0);
	if (strncmp("file", val->name, 4)) {
    	X509V3err(X509V3_F_V2I_HYBRIDKEY, X509V3_R_INVALID_OPTION);
		goto err;
	}
	if (!(pubkey = BIO_new_file(val->value, "rb"))) {
    	X509V3err(X509V3_F_V2I_HYBRIDKEY, X509V3_R_FAILURE_OPENING_KEY_FILE);
		goto err;
	}
	if ((ext = X509_PUBKEY_new()) == NULL) {
    	X509V3err(X509V3_F_V2I_HYBRIDKEY, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if ((pkey = PEM_read_bio_PUBKEY(pubkey, NULL, NULL, NULL)) == NULL) {
    	X509V3err(X509V3_F_V2I_HYBRIDKEY, X509V3_R_FAILURE_READING_KEY_FILE);
		goto err;
	}
	if(!X509_PUBKEY_set(&ext, pkey)) {
		goto err;
	}
	return ext;

 err:
 	if (ext)
 		X509_PUBKEY_free(ext);
 	if (pubkey)
 		BIO_free(pubkey);
 	if (pkey)
 		EVP_PKEY_free(pkey);
	return NULL;
}

static int i2r_HybridKey(const X509V3_EXT_METHOD *method,
                            void *ext, BIO *out, int indent)
{
	X509_PUBKEY *xpkey = ext;
	ASN1_OBJECT *xpoid;
	X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, xpkey);
	if (BIO_printf(out, "%*sSubject Public Key Info:\n", indent, "") <= 0)
		return 0;
	if (BIO_printf(out, "%*sPublic Key Algorithm: ", indent + 4, "") <= 0)
		return 0;
	if (i2a_ASN1_OBJECT(out, xpoid) <= 0)
		return 0;
	if (BIO_puts(out, "\n") <= 0)
		return 0;

	EVP_PKEY* pkey = X509_PUBKEY_get0(xpkey);
	if (pkey == NULL) {
		BIO_printf(out, "%*sUnable to load Public Key\n", indent + 4, "");
		ERR_print_errors(out);
	} else {
		EVP_PKEY_print_public(out, pkey, indent + 8, NULL);
	}
	return 1;
}

const X509V3_EXT_METHOD v3_hybrid_key = {
    NID_hybrid_key,   		/* .ext_nid = */
    0,                      /* .ext_flags = */
    ASN1_ITEM_ref(X509_PUBKEY), /* .it = */
    NULL, NULL, NULL, NULL,
    NULL,                   /* .i2s = */
    NULL,                   /* .s2i = */
    NULL,                   /* .i2v = */
	v2i_HybridKey,          /* .v2i = */
	i2r_HybridKey,			/* .i2r = */
    NULL,                   /* .r2i = */
    NULL                    /* extension-specific data */
};

// if the certificate contains an inner public key it is returned, otherwise a null pointer is returned
EVP_PKEY* X509_get_hybrid_key(X509* x) {
    int i;
	X509_EXTENSION* ext;
    X509_PUBKEY* hk;

    // get the hybrid signature extension
    if ((i = X509_get_ext_by_NID(x, NID_hybrid_key, -1)) < 0) {
    	return NULL;
    }
	if ((ext = X509_get_ext(x, i)) == NULL) {
		return NULL;
	}
    if ((hk = X509V3_EXT_d2i(ext)) == NULL) {
    	return NULL;
    }
    return X509_PUBKEY_get0(hk);
}
