## Support PSS signatures in RSA verification

This gem requires that ruby be built against OpenSSL 1.0.1 or higher! Earlier versions don't support PSS signature verification.

### Usage

```ruby
require 'openssl_rsa_pss_verify'
pubkey = OpenSSL::PKey::RSA.new File.read("my_pubkey.pem")
raw_data = File.read("my_raw_data")
signature = File.read("my_signature")
salt_lenth = 0

pubkey.verify_pss_sha1(signature, 
                       OpenSSL::Digest::SHA1.digest(raw_data), 
                       salt_length)
#=> true or false
```

This the above is identical to
```bash
openssl sha1 -binary my_raw_data > my_hashed_data
openssl pkeyutl -verify -in my_hashed_data -pubin -inkey my_pubkey.pem \
  -sigfile my_signature -pkeyopt digest:sha1 -pkeyopt rsa_padding_mode:pss \
  -pkeyopt rsa_pss_saltlen:0
```

See the [man page](https://www.openssl.org/docs/apps/pkeyutl.html) for more information.

### Notes

- Only supports SHA1
- OpenSSL 1.0.1 is not available on Heroku! I'm working on a custom buildpack, but it's very ad hoc.
