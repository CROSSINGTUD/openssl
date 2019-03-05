#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <internal/x509_int.h>
#include <string.h>

typedef struct HybridSig_st {
	X509_ALGOR* algor;
	ASN1_BIT_STRING* sig;
} HybridSig;

ASN1_SEQUENCE(HybridSig) = {
	ASN1_SIMPLE(HybridSig, algor, X509_ALGOR),
	ASN1_SIMPLE(HybridSig, sig, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(HybridSig)

IMPLEMENT_ASN1_FUNCTIONS(HybridSig)

/* A function to generate an hybridSig extension that contains all 0's as the signature string.
 * This form is used for signing and verifying.
 */
HybridSig* create_dummy_extension(EVP_PKEY* key, X509_ALGOR* alg);

static void *v2i_HybridSig(const struct v3_ext_method *method,
        struct v3_ext_ctx *ctx,
        STACK_OF(CONF_VALUE) *values)
{
	HybridSig* hs = NULL;
	BIO *privkey = NULL;
	EVP_PKEY* privateKey = NULL;

	//we need exactly one value, specifying the secret key file
	if (sk_CONF_VALUE_num(values) != 1) {
    	X509V3err(X509V3_F_V2I_HYBRIDSIG, X509V3_R_INVALID_OPTION);
		goto err;
	}
	CONF_VALUE *val = sk_CONF_VALUE_value(values, 0);
	if (strncmp("file", val->name, 4)) {
    	X509V3err(X509V3_F_V2I_HYBRIDSIG, X509V3_R_INVALID_OPTION);
		goto err;
	}
	if (!(privkey = BIO_new_file(val->value, "rb"))) {
    	X509V3err(X509V3_F_V2I_HYBRIDSIG, X509V3_R_FAILURE_OPENING_KEY_FILE);
		goto err;
	}
	if ((privateKey = PEM_read_bio_PrivateKey(privkey, NULL, NULL, NULL)) == NULL) {
    	X509V3err(X509V3_F_V2I_HYBRIDSIG, X509V3_R_FAILURE_READING_KEY_FILE);
		goto err;
	}
	if ((hs = create_dummy_extension(privateKey, NULL)) == NULL) {
		// Error set by createDummyExtension, so we do not need to set any.
		goto err;
	}
	if (ctx->flags & CTX_TEST) {
		return hs;
	}
	ctx->subject_cert->hybrid_sig_private_key = privateKey;
	return hs;

 err:
 	if (hs) {
 		HybridSig_free(hs);
 	}
 	return NULL;
}

static int i2r_HybridSig(const X509V3_EXT_METHOD *method,
                            void *ext, BIO *out, int indent)
{
	HybridSig* sig = ext;
    if (BIO_printf(out, "%*sSignature Algorithm: ", indent, "") <= 0) {
        return 0;
    }
    if (i2a_ASN1_OBJECT(out, sig->algor->algorithm) <= 0) {
        return 0;
    }
	BIO_printf(out, "\n%*sSignature dump:", indent, "");
	return X509_signature_dump(out, sig->sig, indent + 4);
}
static int HYBRID_SIGNATURE_verify(X509* x, EVP_PKEY* public_key);

const X509V3_EXT_METHOD v3_hybrid_sig = {
    NID_hybrid_sig,   		/* .ext_nid = */
    0,                      /* .ext_flags = */
    ASN1_ITEM_ref(HybridSig), /* .it = */
    NULL, NULL, NULL, NULL,
    NULL,                   /* .i2s = */
    NULL,                   /* .s2i = */
    NULL,                   /* .i2v = */
	v2i_HybridSig,	        /* .v2i = */
	i2r_HybridSig,			/* .i2r = */
    NULL,                   /* .r2i = */
    NULL                    /* extension-specific data */
};

void HYBRID_SIGNATURE_sign(X509* x) {
    int i;
	X509_EXTENSION* ext;
    ASN1_OCTET_STRING *ext_oct = NULL;
	EVP_PKEY* private_key;
	HybridSig* hs;
    int ext_len;
    unsigned char *ext_der = NULL;
    if ((i = X509_get_ext_by_NID(x, NID_hybrid_sig, -1)) < 0) {
    	// No extension to be signed
    	return;
    }
	if ((ext = X509_get_ext(x, i)) == NULL) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_SIGN, X509V3_R_NO_HYBRID_SIGNATURE_EXTENSION);
		return;
	}
	if ((private_key = x->hybrid_sig_private_key) == NULL) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_SIGN, X509V3_R_NO_KEY_FOR_HYBRID_SIGNATURE);
		return;
	}
	if ((hs = create_dummy_extension(private_key, NULL)) == NULL) {
		// Error set by createDummyExtension, so we do not need to set any.
		return;
	}
	if (ASN1_item_sign(ASN1_ITEM_rptr(X509_CINF), NULL,
								   NULL, hs->sig, &x->cert_info, private_key,
								   NULL) == 0) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_SIGN, X509V3_R_HYBRID_SIGNATURE_SIGNING_FAILURE);
		return;
	}
    ext_der = NULL;
    ext_len = ASN1_item_i2d((void*)hs, &ext_der, ASN1_ITEM_ptr(v3_hybrid_sig.it));
    if (ext_len < 0) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_SIGN, X509V3_R_HYBRID_SIGNATURE_SIGNING_FAILURE);
		return;
	}
    if ((ext_oct = ASN1_OCTET_STRING_new()) == NULL) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_SIGN, ERR_R_MALLOC_FAILURE);
		return;
	}
    ext_oct->data = ext_der;
    ext_oct->length = ext_len;
	if (X509_EXTENSION_set_data(ext, ext_oct) != 1) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_SIGN, X509V3_R_HYBRID_SIGNATURE_SIGNING_FAILURE);
	}
    x->cert_info.enc.modified = 1;
}

static int HYBRID_SIGNATURE_verify(X509* x, EVP_PKEY* public_key) {
    int i;
	X509_EXTENSION* ext;
    ASN1_OCTET_STRING *extoct;
	HybridSig* dummy;
    int ext_len;
    unsigned char *ext_der = NULL;
    HybridSig *hs = NULL;
    ASN1_OCTET_STRING* ext_oct;
    ASN1_BIT_STRING* signature;

    // get the hybrid signature extension
    if ((i = X509_get_ext_by_NID(x, NID_hybrid_sig, -1)) < 0) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_VERIFY, X509V3_R_NO_HYBRID_SIGNATURE_TO_VERIFY);
    	return 0;
    }
	if ((ext = X509_get_ext(x, i)) == NULL) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_VERIFY, X509V3_R_NO_HYBRID_SIGNATURE_TO_VERIFY);
		return 0;
	}
    extoct = ASN1_OCTET_STRING_dup(X509_EXTENSION_get_data(ext));
    if ((hs = X509V3_EXT_d2i(ext)) == NULL) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_VERIFY, X509V3_R_HYBRID_SIGNATURE_PARSING_FAILURE);
    	return 0;
    }
    signature = ASN1_STRING_dup(hs->sig);

    //create a dummy extension for verification (contains all 0's as the signature string)
    if ((dummy = create_dummy_extension(public_key, hs->algor)) == NULL) {
		// Error set by createDummyExtension, so we do not need to set any.
    	return 0;
    }
    ext_len = ASN1_item_i2d((void*)dummy, &ext_der, ASN1_ITEM_ptr(v3_hybrid_sig.it));
    if (ext_len < 0) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_VERIFY, X509V3_R_HYBRID_SIGNATURE_PARSING_FAILURE);
		return 0;
	}
    if ((ext_oct = ASN1_OCTET_STRING_new()) == NULL) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_VERIFY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
    ext_oct->data = ext_der;
    ext_oct->length = ext_len;
    //replace the extension data with the dummy extension data
	if (X509_EXTENSION_set_data(ext, ext_oct) != 1) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_VERIFY, X509V3_R_HYBRID_SIGNATURE_VERIFICATION_FAILURE);
		return 0;
	}
	x->cert_info.enc.modified = 1;

	//verify the hybrid signature
    if (ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF), hs->algor, signature, &x->cert_info, public_key) != 1) {
    	X509V3err(X509V3_F_HYBRID_SIGNATURE_VERIFY, X509V3_R_HYBRID_SIGNATURE_VERIFICATION_FAILURE);
        //restore the extension to its original state for further verification
        X509_EXTENSION_set_data(ext, extoct);
    	return 0;
    }

    //restore the extension to its original state for further verification
    X509_EXTENSION_set_data(ext, extoct);
	x->cert_info.enc.modified = 1;

	return 1;
}

static int hybrid_sig_validate_path_internal(X509_STORE_CTX *ctx,
                                       	     STACK_OF(X509) *chain) {
	EVP_PKEY* public_key;
	int i;
	X509 *x;
    bool need_pubkey = false; // if one certificate has a hybrid key, all others upwards in the chain need one as well

	i = 0;
	x = sk_X509_value(chain, i);

	/*
	 * Walk up the chain. Verify each hybrid signature with the hybrid key of the parent.
	 */
	for (; i < sk_X509_num(chain) - 1; i++) {
		X509* parent = sk_X509_value(chain, i + 1);
		public_key = X509_get_hybrid_key(parent);
		if (!public_key) {
			if (need_pubkey) {
				ctx->error = X509_V_ERR_HYBRID_SIG_VERIFY_FAIL;
				ctx->error_depth = i;
				ctx->current_cert = x;
				if (ctx->verify_cb(0, ctx) == 0)
					return 0;
			}
			// we do not have a hybrid key, but we do not need one. Continue checking the chain
			continue;
		}
		else {
			// this certificate has a hybridkey -> all parent certificates need to have one as well
			need_pubkey = true;
		}
		if (HYBRID_SIGNATURE_verify(x, public_key) == 0) {
			ctx->error = X509_V_ERR_HYBRID_SIG_VERIFY_FAIL;
			ctx->error_depth = i;
			ctx->current_cert = x;
			if (ctx->verify_cb(0, ctx) == 0)
				return 0;
		}
		x = parent;
	}

	// Check self signed hybrid signature of the root certificate.
	public_key = X509_get_hybrid_key(x);
	if (!public_key) {
		if (need_pubkey) {
			ctx->error = X509_V_ERR_HYBRID_SIG_VERIFY_FAIL;
			ctx->error_depth = i;
			ctx->current_cert = x;
			if (ctx->verify_cb(0, ctx) == 0)
				return 0;
		}
		return 1; // we do not need a hybrid key -> all is good :)
	}
	return HYBRID_SIGNATURE_verify(x, public_key);
}

/*
 * Verify a the hybrid signatures for a certificate chain.
 */
int X509v3_hybrid_sig_validate_path(X509_STORE_CTX *ctx) {
	if (ctx->chain == NULL
            || sk_X509_num(ctx->chain) == 0
            || ctx->verify_cb == NULL) {
        ctx->error = X509_V_ERR_UNSPECIFIED;
        return 0;
    }
    return hybrid_sig_validate_path_internal(ctx, ctx->chain);
}

HybridSig* create_dummy_extension(EVP_PKEY* key, X509_ALGOR* alg) {
	HybridSig* hs;
	int signatureLength;

	if ((hs = HybridSig_new()) == NULL) {
		X509V3err(X509V3_F_CREATE_DUMMY_EXTENSION, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	signatureLength = EVP_PKEY_size(key);

	if (alg == NULL) {
		X509_PUBKEY* pk = NULL;
		if ((pk = X509_PUBKEY_new()) == NULL) {
			X509V3err(X509V3_F_CREATE_DUMMY_EXTENSION, ERR_R_MALLOC_FAILURE);
			goto err;
		}
		if(!X509_PUBKEY_set(&pk, key)) {
			X509V3err(X509V3_F_CREATE_DUMMY_EXTENSION, X509V3_R_BAD_HYBRID_SIGNATURE_ALGORITHM);
			goto err;
		}
		if (!X509_PUBKEY_get0_param(NULL, NULL, NULL, &alg, pk)){
			X509V3err(X509V3_F_CREATE_DUMMY_EXTENSION, X509V3_R_BAD_HYBRID_SIGNATURE_ALGORITHM);
			goto err;
		}
	}
	hs->algor = alg;

	if (hs->sig->data) {
		OPENSSL_free(hs->sig->data);
	}
	if ((hs->sig->data = OPENSSL_zalloc(signatureLength)) == NULL) {
		X509V3err(X509V3_F_CREATE_DUMMY_EXTENSION, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	hs->sig->length = signatureLength;
	hs->sig->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
	hs->sig->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	return hs;

 err:
	if (hs) {
		HybridSig_free(hs);
	}
	return NULL;
}
