# FiatShamirIdentification
C# OOP implementation of Fiat Shamir Identification Scheme

Library includes the classes:

	-PrivateKey
  	-PublicKey
	-Proover
	-Verifier

These classes provide key creation, key-bytes conversion, and the Fiat Shamir Identification protocol.
The library supports multithread key creation.

*Random Number Generator*  
User can using a your own subclass of .NET RandomNumberGenerator abstract class.

*Usage:*

    a)the client create a private key with PrivateKey.NewKey static method
    b)the client generate a public key from the private key with GetPublicKey and send this to the server
    c)the client instantiates a Proover from the private key with GetProover
    c)the server instantiates a Verifier from the public key with GetVerifier
    d)run a session of the protocol exchanging the result of methods for N iteration, with N is the precision you like:

        1)Client: Proover.Step1 -> Server
        2)Server: Verifier.Step1 -> Client
        3)Client: Proover.Step2 -> Server
        4)Server: Verifier.Step2 -> result of identification
        4.1)Server: Verifier.CheckState -> result of identification
