require 'mkmf'

openssl_path = File.expand_path("../../../vendor/openssl", __FILE__)

dir_config('', File.join(openssl_path, "lib"), File.join(openssl_path, "include"))

if have_const("RSA_PKCS1_PSS_PADDING", "openssl/rsa.h")
  create_makefile('openssl_rsa_pss_verify')
else
  fail "libcyrpto not found or too old!"
end
