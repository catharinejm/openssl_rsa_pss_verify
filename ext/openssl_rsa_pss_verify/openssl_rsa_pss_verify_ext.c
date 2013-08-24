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

static enum ORPV_errors {
  OK,
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
} err = OK;

struct ORPV_error_vals {
  VALUE errClass;
  const char * msg;
  char * ossl_errs;
  BIO * bio_err;
};

#define BIND_ERR_STR(str_p) \
  if (ERR_peek_error()) ERR_error_string(ERR_get_error(), (str_p));

static char * read_errors(BIO * bio_err, char ** buf) {
  BUF_MEM * bmem;
  bio_err = BIO_new(BIO_s_mem());
  ERR_print_errors(bio_err);
  BIO_get_mem_ptr(bio_err, &bmem);
  *buf = BUF_strdup(bmem->data);
  return *buf;
}

static VALUE cleanup_bio(VALUE arg) {
  struct ORPV_error_vals * errs = (struct ORPV_error_vals*)arg;
  BIO_free(errs->bio_err);
  OPENSSL_free(errs->ossl_errs);
  return Qnil;
}

VALUE raise_ossl_errors(VALUE arg) {
  struct ORPV_error_vals * errs = (struct ORPV_error_vals*)arg;
  if (errs->ossl_errs)
    rb_raise(errs->errClass, "%s\n%s", errs->msg, errs->ossl_errs);
  else
    rb_raise(errs->errClass, "%s", errs->msg);

  return Qnil;
}

VALUE ORPV__verify_pss_sha1(VALUE self, VALUE vPubKey, VALUE vSig, VALUE vHashData, VALUE vSaltLen) {
  BIO * pkey_bio = NULL;
  RSA * rsa_pub_key = NULL;
  EVP_PKEY * pkey = NULL;
  EVP_PKEY_CTX * pkey_ctx = NULL;
  char * pub_key = NULL;
  
  int verify_rval = -1, salt_len;
  char ossl_err_str[120] = "[no internal OpenSSL error was flagged]";
  struct ORPV_error_vals error_vals;

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
          BIND_ERR_STR(ossl_err_str)
          rb_raise(rb_cRSAError, "An error occurred during validation.\n%s", ossl_err_str);
      }
      break;

    case KEY_OVERFLOW:
      rb_raise(rb_cRSAError, "Your public key is too big. How is that even possible?");
      break;
    case NOMEM:
      rb_raise(rb_const_get_at(rb_mErrno, rb_intern("ENOMEM")), "Insufficient memory to allocate pubkey copy. Woof.");
      break;
    case PUBKEY_PARSE:
      BIND_ERR_STR(ossl_err_str);
      rb_raise(rb_cRSAError, "Error parsing public key\n%s", ossl_err_str);
      break;
    case PKEY_INIT:
      BIND_ERR_STR(ossl_err_str);
      rb_raise(rb_cRSAError, "Failed to initialize PKEY\n%s", ossl_err_str);
      break;
    case RSA_ASSIGN:
      BIND_ERR_STR(ossl_err_str);
      rb_raise(rb_cRSAError, "Failed to assign RSA object to PKEY\n%s", ossl_err_str);
      break;
    case PKEY_CTX_INIT:
      error_vals.errClass = rb_cRSAError;
      error_vals.msg = "Failed to initialize PKEY context.";
      read_errors(error_vals.bio_err, &error_vals.ossl_errs);

      rb_ensure(&raise_ossl_errors, (VALUE)&error_vals, &cleanup_bio, (VALUE)&error_vals);

      break;
    case VERIFY_INIT:
      BIND_ERR_STR(ossl_err_str);
      rb_raise(rb_cRSAError, "Failed to initialize verification process.\n%s", ossl_err_str);
      break;
    case SET_SIG_MD:
      BIND_ERR_STR(ossl_err_str);
      rb_raise(rb_cRSAError, "Failed to set signature message digest to SHA1.\n%s", ossl_err_str);
      break;
    case SET_PADDING:
      BIND_ERR_STR(ossl_err_str);
      rb_raise(rb_cRSAError, "Failed to set PSS padding.\n%s", ossl_err_str);
      break;
    case SET_SALTLEN:
      BIND_ERR_STR(ossl_err_str);
      rb_raise(rb_cRSAError, "Failed to set salt length.\n%s", ossl_err_str);
      break;
    default:
      BIND_ERR_STR(ossl_err_str);
      rb_raise(rb_eRuntimeError, "Something has gone horribly wrong.\n%s", ossl_err_str);
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
