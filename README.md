# FiatShamirIdentification
C# OOP implementation of Fiat Shamir Identification Scheme

Library includes:

	-KeyGen class
	-Proover class
	-Verifier class

The library supports multithread key creation

*Random Number Generator*

User can using a your own subclass of .NET RandomNumberGenerator abstract class.

*Usage:*

    a)the client create the keys with KeyGen
    b)the client instantiates a Proover object with the private key
    c)the server instantiates a Verifier object with the public key of client
    d)run a session of the protocol exchanging the result of methods for N iteration, with N is the precision you like:

        1)Client: Proover.step1 -> Server
        2)Server: Verifier.step1 -> Client
        3)Client: Proover.step2 -> Server
        4)Server: Verifier.step2 -> result of identification
        4.1)Server: Verifier.checkstate -> result of identification
