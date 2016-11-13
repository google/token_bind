To compile the example server against OpenSSL, use version 1.1.0 or newer.  If
you use resumption, a 1-line patch needs to be applied to the OpenSSL source so
that custom extensions can be negotiated on resume:

  openssl$ git apply <path/to/token_bind/example>/custom_ext_resume.patch

Then rebuild openssl.  The Makefile targets assume you have created a symbolic
link to the openssl source directory in the token_bind directory:

  token_bind$ ln -s <path/to/openssl/source>/openssl .

Then to build:

  token_bind$ make
  token_bind$ cd example
  example$ make

To run the example server:

  example$ ./server

You should be able to connect to it by running a recent version of Chrome and
connect to this server at localhost:40000.  It will say "Token binding not
negotiated" if Chrome is not configured to speak token binding.  Check
about:flags, and make sure you enable the token binding flag.

You can run the "runtest.sh" test to see if everything is working.
