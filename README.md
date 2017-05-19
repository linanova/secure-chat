## Work In Progress

This simple secure communication channel is being written as an exercise in Go and cryptography.

### Basics
Can be run in two modes - 'server' and 'client' that define which side initiates the connection and which side listens for it. Note only one connection is formed so the 'server' is not technically a server.

Assumes that the two end users have each generated a RSA key pair. They need to provide a file containing their private key, and a file containing the peer's public key.

Aims to implement EDH with RSA, and encrypt communication with AES in GCM mode.

### todos
The goal is to implement ephemeral Diffie Hellman for perfect forward secrecy (after all, otherwise we could have just used the provided RSA keys for the communication). So, a new key needs to be generated for each session. How is a session defined in this context? The current implementation already fits the "ephemeral" criteria if we consider a session to be one run of the program (until one side terminates the connection). That is, unlike static DH, the key used will not be the same for any two connections between the same users.

However, it may still be beneficial to have a regular refresh of the key within the same connection. The IV used for the GCM mode encryption is entirely random (as opposed to a counter which would be more standard). This means if the connection were to hypothetically persist for a long time, after a large number of messages were exchanged, the likelihood of a dupe IV increases, and this could compromise the session key.
