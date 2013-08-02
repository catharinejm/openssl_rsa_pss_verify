require 'mkmf'

if find_library("crypto", "EVP_PKEY_CTX_new", ENV["LD_LIBRARY_PATH"] || "")
  create_makefile('openssl_rsa_pss_verify')
else
  raise "libcyrpto not found or too old!"
end
