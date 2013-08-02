require 'mkmf'

dir_config('', ENV["LD_LIBRARY_PATH"]||"", ENV["C_INCLUDE_PATH"]||"")

if have_const("RSA_PKCS1_PSS_PADDING", "openssl/rsa.h")
  create_makefile('openssl_rsa_pss_verify')
else
  raise "libcyrpto not found or too old!"
end
