#Mini Digital Signature Protocol Realisation
It utilizes some variation of El-Gamal digital signature scheme along with hash function built with Merkle-Damgard scheme.
Architecture of application is quite simple, but there presented few levels of logic. Long arithmetics is provided by repository:
https://github.com/juja256/long_arithmetic
On the top level there is class AbonentKeyStore - memory storage for user generated keys and SignedMessage - class representing
signed messages in specific format.
Level down there is class AlgsFactory that provides realisations of some cryptographic primitives such block ciphers,
hash functions and signing-verification algorithms in El-Gamal protocol.
