require 'mkmf'

openssl_path = File.expand_path("../../../vendor/openssl", __FILE__)

if RUBY_PLATFORM =~ /linux/
  $LDFLAGS << "-L#{openssl_path}/lib"
  $LDFLAGS << "-lcrypto"
  $CFLAGS << "-I#{openssl_path}/include"
end

if have_const("RSA_PKCS1_PSS_PADDING", "openssl/rsa.h")
  create_makefile('openssl_rsa_pss_verify')
else
  fail "libcyrpto not found or too old!"
end
