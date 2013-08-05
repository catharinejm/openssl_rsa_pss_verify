require 'mkmf'

if have_const("RSA_PKCS1_PSS_PADDING", "openssl/rsa.h")
  create_makefile('openssl_rsa_pss_verify')
else
  fail "libcyrpto not found or too old!"
end
