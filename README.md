# Key management made simple.

This security provider aims to make key management in java more simple to use.

It can read content from many key store.

It can load other security providers

It can be used as an agent, instead of having complex variable name to use.

Common use case is :

    java -java -javaagent:.../SimpleProvider.jar=.../config.ini
    
The config file is a ini-like file with two sections : stores and provides.

An example is :

    [stores]
    jks=.../somethine.jks
    jks:password=.../somethine.jks
    default
    system
    [Providers]
    org.bouncycastle.jce.provider.BouncyCastleProvider
    org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
    services

The line `type:password=file` gives the path to a key store with an optional password.
`default` loads the default keystores for this JVM.
`system` try to identify the default key store for this system (`KeychainStore` or `Windows-ROOT`)

It adds the support for the type `pem` that allows to store PEM encoded certificates chain or individual certificate.

Providers settings take either a class name or try to load all providers declared as a service (see http://docs.oracle.com/javase/8/docs/api/java/util/ServiceLoader.html).

It uses internally some properties so the command line argument and security properties for those are ignore.

It sets the following properties:

 * javax.net.ssl.trustStoreType
 * javax.net.ssl.keyStoreType
 * javax.net.ssl.trustStore
 * javax.net.ssl.keyStore
 
And the the following security property:

 * keystore.type
