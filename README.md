# sigma

1-out-of-N proofs are public coin **Σ-protocols of knowledge of one out of N Pedersen commitments is opening to 0**.
This repository contains implementations and test suites for 1-out-of-N proofs described in [https://eprint.iacr.org/2015/643.pdf],
and also  the implementation of the **Zerocoin scheme** implemented through 1-out-of-N Proofs as is described in the paper  [1-out-of-N Proofs  Or How to Leak a Secret and Spend a Coin, Groth & Kohlweiss, https://eprint.iacr.org/2014/764.pdf]

### Directory layout

````
   .
   ├── src              # Source code for the protocol & schema
   ├── bitcoin          # Slightly modified source code from bitcoin
   ├── secp256k1        # Slightly modified source code from secp256k1
   ├── tests            # Test executables
   ├── build            # Script to build executables in tests (Linux & MacOS)
   ├── run_all_tests    # Script to run all tests together
   └── README.mdℤ
````


The code can be compiled using the following command from the root directory of the repository.

``./build <directory>``

For example, ``build ~/macos`` will put the executables ``protocol_tests``, ``r1_test``, ``serialize_test``, ``sigma_primitive_types_test``, ``coin_tests``, ``coin_tests`` and ``coin_spend_tests`` in the directory ``~/macos``.


### Group

 The elliptic curve group ``secp256k1`` used in Bitcoin.

### Executables

### ``protocol_tests``

The executable protocol_tests runs sigma proof generation and verification tests. It creates random anonymity set, puts there there 0, generates proof and tries to verify.
    1. one_out_of_n:                        It creates valid proof and verifies.
    2  prove_and_verify_in_different_set:   Proof is valid but anonymity set is modified.
    3. prove_coin_out_of_index              The index of coin is out of the set.
    4. prove_coin_not_in_set                Coin at provided index is not 0;

### ``r1_tests``

The executable r1_tests runs tests for R1 relation. R1

### ``serialize_test``

The executable serialization_test runs tests for EC Group element, Scalar and Sigma proof. It serializes the object, deserializes it to another object and compares them.

### ``coin_spend_tests``

The executable coin_spend_tests runs tests for whole schema.

````
