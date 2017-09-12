Assignment 3 of course SIL765: Networks and System Security

You are required to (a) build a CA, and (b) build clients that wish to send messages suitably encrypted with public key of receiver, but only after they know the other client’s public key in a secure manner. There are two ways for client A to know the public key of another client, B: (a) get it from CA (which is rarely done), or receive a “certificate” from B itself. We will presently limit the fields in the “certificate” to the following:
CERTA = ENCPRX (IDA, KUA, TA, DURA, INFOCA)
where
* PRX is private key of certification authority (PUX is public key of certification authority)
* IDA is user ID,
* KUA is public key of A,
* TA is time of issuance of certificate.
To do so, you will need to:
* ensure that clients already (somehow) know the public key of the certification authority,
* CA has the public keys of all the clients, and corresponding to which the clients themselves have their corresponding private keys with themselves,
* messages between CA and clients are encrypted using RSA algorithm (with fixed parameters (n, p, q)) and using CA’s private key,
* messages sent/received between clients (once they have each other client’s public key) are encrypted using RSA algorithm using the same parameters (n, p, q).
find a way to generate and encode “current time”.
Once the public keys have become known to the clients, the clients should encrypt and send “hello xxx” message using their private keys.
