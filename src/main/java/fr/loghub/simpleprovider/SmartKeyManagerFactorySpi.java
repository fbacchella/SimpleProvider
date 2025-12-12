package fr.loghub.simpleprovider;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;

public class SmartKeyManagerFactorySpi extends KeyManagerFactorySpi {

    public record Parameters(KeyManagerFactory factory, Set<Principal> trustedIssuers, String clientAlias)
            implements ManagerFactoryParameters {
    }

    private KeyManagerFactory wrapped;
    Set<Principal> trustedIssuers;
    String clientAlias;

    @Override
    protected void engineInit(KeyStore keyStore, char[] chars)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        wrapped = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        wrapped.init(keyStore, chars);
        trustedIssuers = null;
        clientAlias = null;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters params) {
        if (params instanceof Parameters smartParams) {
            wrapped = smartParams.factory;
            trustedIssuers = smartParams.trustedIssuers;
            clientAlias = smartParams.clientAlias;
        }
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        KeyManager[] parent = wrapped.getKeyManagers();
        return Arrays.stream(parent).map(this::wrap).toArray(KeyManager[]::new);
    }

    private KeyManager wrap(KeyManager km) {
        if (km instanceof X509ExtendedKeyManager x509km) {
            return new SmartKeyManager(x509km, trustedIssuers, clientAlias);
        } else {
            return km;
        }
    }

}
