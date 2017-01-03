package fr.jrds;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.util.Arrays;

public class TestSmartPki {

    public static void main(String[] args) throws KeyStoreException {
        System.out.println("all provides: " + Arrays.toString(Security.getProviders()));
        KeyStore ks = KeyStore.getInstance("SPKI");
        System.out.println(ks);
    }

}
