# Nodejs Crypto package for the browser

This is an alternative crypto-browserify implementation. It includes several algorithms implemented
in pure-javascript, accessible trogh a NodeJS compatible API making it possible to port NodeJS crypto
applications to the browser with the help of browserify.

## Sources

Mose of the code has been ported from the following projects:

* [jsbn by Tom Wu] (http://www-cs-students.stanford.edu/~tjw/jsbn/)
* [crypto-js] (http://code.google.com/p/crypto-js/)
* [cryptico] (http://wwwtyro.github.io/cryptico/)

Some other algorithms have been originally implemented as part of this project.

## Implemented Algorithms

### Core

Several algorigms are based on Tom Wu's Big Integer. Including SecureRandom by David Bau. An specializaiton
of Math, called SecureMath is also provided by replacing some methods with crytographic variants.

### Hashes

Note: the implementation is functional, and streamable. However, the Hashes do not inherit from Stream yet.

Implemented: sha1,sha225,sha256,sha512,sha3,sha284,md5

Source: cryptojs v3

### Diffie Hellman

An orginal impelmentation is provided based on the ported BigInteger library.

Supported standard groups: modp2, modp14


### Ciphers

Implemented: EAS

### HMAC

Implemented: md5-hmac

## Tests

The provided unit tests fit into two categories:

* Functional tests to check that the port works/is functional.
* Functional tests to check that this implementation produces interoperable results with NodeJS's crypto module.