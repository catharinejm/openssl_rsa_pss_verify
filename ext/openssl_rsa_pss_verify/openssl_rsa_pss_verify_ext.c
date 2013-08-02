#include <ruby.h>

#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

VALUE rb_mOpenSSL;
VALUE rb_mPKey;
VALUE rb_cRSA;
VALUE rb_cRSAError;

VALUE __openssl_rsa_pss_verify(VALUE self, VALUE vSig, VALUE vData, VALUE vSaltLen) {
  EVP_PKEY * pkey;
  RSA * rsa_pub_key;

  int salt_len = NUM2INT(vSaltLen), verify_rval;

  unsigned char * sig_bytes, * data_bytes;

  StringValue(vSig);
  StringValue(vData);

  sig_bytes = malloc(RSTRING_LEN(vSig));
  data_bytes = malloc(RSTRING_LEN(vData));

  memcpy(sig_bytes, RSTRING_PTR(vSig), RSTRING_LEN(vSig));
  memcpy(data_bytes, RSTRING_PTR(vData), RSTRING_LEN(vData));

  Data_Get_Struct(self, EVP_PKEY, pkey);
  rsa_pub_key = RSAPublicKey_dup(pkey->pkey.rsa);

  // int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
  // 			const unsigned char *mHash,
  // 			const EVP_MD *Hash, int sLen);
  RSA_padding_add_PKCS1_PSS(rsa_pub_key, sig_bytes, data_bytes, EVP_sha1(), salt_len);

  // int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
  //       const EVP_MD *Hash, const unsigned char *EM, int sLen);
  verify_rval = RSA_verify_PKCS1_PSS(rsa_pub_key, data_bytes, EVP_sha1(), sig_bytes, salt_len);
  free(sig_bytes);
  free(data_bytes);

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
  rb_mOpenSSL = rb_const_get_at(rb_cObject, rb_intern("OpenSSL"));
  rb_mPKey = rb_const_get_at(rb_mOpenSSL, rb_intern("PKey"));
  rb_cRSA = rb_const_get_at(rb_mPKey, rb_intern("RSA"));
  rb_cRSAError = rb_const_get_at(rb_mPKey, rb_intern("RSAError"));

  rb_define_method(rb_cRSA, "verify_pss", __openssl_rsa_pss_verify, 3);
}
