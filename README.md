bc-srp6-extensions
==================

extention for SRP6 key agreement in BouncyCastle 1.49 by Daniele Grasso

According to the SRP key agreement as shown by Tom Wu, there is a part of the logic missing in the current BouncyCastle's implementation: 

	1) calculation of the "evidence messages", corresponding to messages M1 and M2 to perform mutual authentication

	2) calculation of the Key K as a hash of the secret S

My extensions to the classes SRP6Server, SRP6Client and SRP6Utils add this functionality.
I hope this contribution can be helpful. Any suggestion is welcome!

NOTE: this is provided here as an extension of the classes, but you find a fork of the original BC code with the same things integrated at https://github.com/dangrasso/bc-java
