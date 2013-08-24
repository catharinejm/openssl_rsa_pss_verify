require 'openssl'
require "openssl_rsa_pss_verify/openssl_rsa_pss_verify"

class OpenSSL::PKey::RSA
  def verify_pss_sha1(signature, data, saltlen)
    __verify_pss_sha1(public_key.to_pem, signature, OpenSSL::Digest::SHA1.digest(data), saltlen)
  end
end
