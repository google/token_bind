URL: https://github.com/google/token_bind  
Version: 0.10  
License: Apache 2.0  
License File: LICENSE

Description:  
Provides support for token binding according to the following RFCs:

https://tools.ietf.org/html/draft-ietf-tokbind-protocol-10  
https://tools.ietf.org/html/draft-ietf-tokbind-negotiation-05  
https://tools.ietf.org/html/draft-ietf-tokbind-https-06

This token binding library links to OpenSSL to provide token binding negotiation
over TLS, and provides high level functions needed to add token binding support
to HTTP appliactions.

This is compatible with OpenSSL versions 1.1.0 and newer.  It is implemented
using the custom extension API in OpenSSL.  Due to a minor issue
(https://github.com/openssl/openssl/pull/927) in this API, resumption is not
compatible with this token binding library unless a 1-line patch is made (see
example/custom_ext_resume.patch).

This is not an official Google product.
