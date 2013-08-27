#include <ruby.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/opensslv.h>

static VALUE rb_mOpenSSL;
static VALUE rb_mPKey;
static VALUE rb_cRSA;
static VALUE rb_cRSAError;

#define ORPV_MAX_ERRS 10
#define OSSL_ERR_STR_LEN 120

enum ORPV_errors {
  OK,
  EXTERNAL,
  KEY_OVERFLOW,
  NOMEM,
  PUBKEY_PARSE,
  PKEY_INIT,
  RSA_ASSIGN,
  PKEY_CTX_INIT,
  VERIFY_INIT,
  SET_SIG_MD,
  SET_PADDING,
  SET_SALTLEN,
};

static void bind_err_strs(char * strs, int max) {
  int err_cnt;
  char last_err[OSSL_ERR_STR_LEN];

  if (! ERR_peek_error()) {
    strcat(strs, "[no internal OpenSSL error was flagged]");
    return;
  }

  strncat(strs, ERR_error_string(ERR_get_error(), NULL), OSSL_ERR_STR_LEN);
  for(err_cnt = 1; ERR_peek_error() && err_cnt < (max-1); ++err_cnt) {
    strcat(strs, "\n");
    strncat(strs, ERR_error_string(ERR_get_error(), NULL), OSSL_ERR_STR_LEN);
  }

  if (ERR_peek_error()) {
    ERR_error_string_n(ERR_get_error(), last_err, OSSL_ERR_STR_LEN);
    ++err_cnt;
    
    if (ERR_peek_error()) {
      while(ERR_get_error()) ++err_cnt;
      snprintf(last_err, OSSL_ERR_STR_LEN, "[%i additional errors truncated]", (max - err_cnt + 1));
    }
    strcat(strs, "\n");
    strncat(strs, last_err, OSSL_ERR_STR_LEN);
  }
}


static VALUE ORPV__verify_pss_sha1(VALUE self, VALUE vPubKey, VALUE vSig, VALUE vHashData, VALUE vSaltLen) {
  enum ORPV_errors err = OK;

  BIO * pkey_bio = NULL;
  RSA * rsa_pub_key = NULL;
  EVP_PKEY * pkey = NULL;
  EVP_PKEY_CTX * pkey_ctx = NULL;
  char * pub_key = NULL;
  
  int verify_rval = -1, salt_len;
  char ossl_err_strs[(OSSL_ERR_STR_LEN + 2) * ORPV_MAX_ERRS] = "";

  if (ERR_peek_error()) {
    err = EXTERNAL;
    goto Cleanup;
  }

  vPubKey = StringValue(vPubKey);
  vSig = StringValue(vSig);
  vHashData = StringValue(vHashData);
  salt_len = NUM2INT(vSaltLen);

  if (RSTRING_LEN(vPubKey) > (long)INT_MAX) {
    err = KEY_OVERFLOW;
    goto Cleanup;
  }

  pub_key = malloc(RSTRING_LEN(vPubKey));
  if (! pub_key) {
    err = NOMEM;
    goto Cleanup;
  }
  memcpy(pub_key, StringValuePtr(vPubKey), RSTRING_LEN(vPubKey));

  pkey_bio = BIO_new_mem_buf(pub_key, (int)RSTRING_LEN(vPubKey));
  rsa_pub_key = PEM_read_bio_RSA_PUBKEY(pkey_bio, NULL, NULL, NULL);
  if (! rsa_pub_key) {
    err = PUBKEY_PARSE;
    goto Cleanup;
  }

  pkey = EVP_PKEY_new();
  if (! pkey) {
    err = PKEY_INIT;
    goto Cleanup;
  }

  if (! EVP_PKEY_set1_RSA(pkey, rsa_pub_key)) {
    err = RSA_ASSIGN;
    goto Cleanup;
  }

  pkey_ctx = EVP_PKEY_CTX_new(pkey, ENGINE_get_default_RSA());
  if (! pkey_ctx) {
    err = PKEY_CTX_INIT;
    goto Cleanup;
  }

  if (EVP_PKEY_verify_init(pkey_ctx) <= 0) {
    err = VERIFY_INIT;
    goto Cleanup;
  }

  if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, EVP_sha1()) <= 0) {
    err = SET_SIG_MD;
    goto Cleanup;
  }

  if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
    err = SET_PADDING;
    goto Cleanup;
  }

  if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, salt_len) <= 0) {
    err = SET_SALTLEN;
    goto Cleanup;
  }

  verify_rval = EVP_PKEY_verify(pkey_ctx, 
                                (unsigned char*)StringValuePtr(vSig), (size_t)RSTRING_LEN(vSig), 
                                (unsigned char*)StringValuePtr(vHashData), (size_t)RSTRING_LEN(vHashData));

Cleanup:
  /*
   * BIO * pkey_bio = NULL;
   * RSA * rsa_pub_key = NULL;
   * EVP_PKEY * pkey = NULL;
   * EVP_PKEY_CTX * pkey_ctx = NULL;
   * char * pub_key = NULL;
   */
  if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
  if (pkey) EVP_PKEY_free(pkey);
  if (rsa_pub_key) RSA_free(rsa_pub_key);
  if (pkey_bio) BIO_free(pkey_bio);
  if (pub_key) free(pub_key);

  switch (err) {
    case OK:
      switch (verify_rval) {
        case 1:
          return Qtrue;
        case 0:
          return Qfalse;
        default:
          bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
          rb_raise(rb_cRSAError, "An error occurred during validation.\n%s", ossl_err_strs);
      }
      break;

    case EXTERNAL:
      bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
      rb_raise(rb_eRuntimeError, "OpenSSL was in an error state prior to invoking this verification.\n%s", ossl_err_strs);
      break;
    case KEY_OVERFLOW:
      rb_raise(rb_cRSAError, "Your public key is too big. How is that even possible?");
      break;
    case NOMEM:
      rb_raise(rb_const_get_at(rb_mErrno, rb_intern("ENOMEM")), "Insufficient memory to allocate pubkey copy. Woof.");
      break;
    case PUBKEY_PARSE:
      bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
      rb_raise(rb_cRSAError, "Error parsing public key\n%s", ossl_err_strs);
      break;
    case PKEY_INIT:
      bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
      rb_raise(rb_cRSAError, "Failed to initialize PKEY\n%s", ossl_err_strs);
      break;
    case RSA_ASSIGN:
      bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
      rb_raise(rb_cRSAError, "Failed to assign RSA object to PKEY\n%s", ossl_err_strs);
      break;
    case PKEY_CTX_INIT:
      bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
      rb_raise(rb_cRSAError, "Failed to initialize PKEY context.\n%s", ossl_err_strs);
      break;
    case VERIFY_INIT:
      bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
      rb_raise(rb_cRSAError, "Failed to initialize verification process.\n%s", ossl_err_strs);
      break;
    case SET_SIG_MD:
      bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
      rb_raise(rb_cRSAError, "Failed to set signature message digest to SHA1.\n%s", ossl_err_strs);
      break;
    case SET_PADDING:
      bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
      rb_raise(rb_cRSAError, "Failed to set PSS padding.\n%s", ossl_err_strs);
      break;
    case SET_SALTLEN:
      bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
      rb_raise(rb_cRSAError, "Failed to set salt length.\n%s", ossl_err_strs);
      break;
    default:
      bind_err_strs(ossl_err_strs, ORPV_MAX_ERRS);
      rb_raise(rb_eRuntimeError, "Something has gone horribly wrong.\n%s", ossl_err_strs);
  }

  return Qnil;
}


void Init_openssl_rsa_pss_verify() {
  fprintf(stderr, "VERSION: %s\n", SSLeay_version(SSLEAY_VERSION));
  rb_mOpenSSL = rb_const_get_at(rb_cObject, rb_intern("OpenSSL"));
  rb_mPKey = rb_const_get_at(rb_mOpenSSL, rb_intern("PKey"));
  rb_cRSA = rb_const_get_at(rb_mPKey, rb_intern("RSA"));
  rb_cRSAError = rb_const_get_at(rb_mPKey, rb_intern("RSAError"));

  rb_define_private_method(rb_cRSA, "__verify_pss_sha1", ORPV__verify_pss_sha1, 4);
}
