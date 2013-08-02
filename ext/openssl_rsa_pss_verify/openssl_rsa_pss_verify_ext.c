#include <ruby.h>

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/opensslv.h>

static VALUE rb_mOpenSSL;
static VALUE rb_mPKey;
static VALUE rb_cRSA;
static VALUE rb_cRSAError;

VALUE __openssl_rsa_pss_verify(VALUE self, VALUE vSig, VALUE vData, VALUE vSaltLen) {
  EVP_PKEY * pkey;
  int verify_rval;

  StringValue(vSig);
  StringValue(vData);

  Data_Get_Struct(self, EVP_PKEY, pkey);
  EVP_PKEY_CTX * pkey_ctx = EVP_PKEY_CTX_new(pkey, ENGINE_get_default_RSA());

  EVP_PKEY_verify_init(pkey_ctx);
  EVP_PKEY_CTX_set_signature_md(pkey_ctx, EVP_sha1());
  EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, NUM2INT(vSaltLen));

  verify_rval = EVP_PKEY_verify(pkey_ctx, RSTRING_PTR(vSig), RSTRING_LEN(vSig), RSTRING_PTR(vData), RSTRING_LEN(vData));

  EVP_PKEY_CTX_free(pkey_ctx);

  switch (verify_rval) {
    case 1:
    return Qtrue;
    case 0:
    return Qfalse;
    default:
    rb_raise(rb_cRSAError, NULL);
  }
}


void Init_openssl_rsa_pss_verify() {
  fprintf(stderr, "VERSION: %s\n", SSLeay_version(SSLEAY_VERSION));
  rb_mOpenSSL = rb_const_get_at(rb_cObject, rb_intern("OpenSSL"));
  rb_mPKey = rb_const_get_at(rb_mOpenSSL, rb_intern("PKey"));
  rb_cRSA = rb_const_get_at(rb_mPKey, rb_intern("RSA"));
  rb_cRSAError = rb_const_get_at(rb_mPKey, rb_intern("RSAError"));

  rb_define_method(rb_cRSA, "verify_pss", __openssl_rsa_pss_verify, 3);
}
