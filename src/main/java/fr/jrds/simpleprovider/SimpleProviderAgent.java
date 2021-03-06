package fr.jrds.simpleprovider;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ServiceLoader;
import java.util.regex.Matcher;


public class SimpleProviderAgent {
    public static void premain(String agentArgs, Instrumentation ins) {
        Provider smartpki = new SimpleProvider();
        //smartpki.put("config", agentArgs);
        Security.insertProviderAt(smartpki, Security.getProviders().length + 1);

        Security.setProperty("keystore.type", SimpleProvider.NAME);

        System.setProperty("javax.net.ssl.trustStoreType", SimpleProvider.NAME);
        System.setProperty("javax.net.ssl.keyStoreType", SimpleProvider.NAME);
        if (agentArgs != null) {
            System.setProperty("javax.net.ssl.trustStore", agentArgs);
            System.setProperty("javax.net.ssl.keyStore", agentArgs);
        }

        Loader.Consumer c = (Loader.MODE mode, Matcher sectionMatch) -> {
            if (sectionMatch.group("providerclass") != null) {
                loadProvider(sectionMatch.group("providerclass"));
            }
        };
        try {
            InputStream stream = new FileInputStream(agentArgs);
            Loader.parse(stream, Loader.MODE.PROVIDERS, c);
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }
    
    private static void loadProvider(String providerclass) {
        try {
            // Load providers declared as service
            if("services".equals(providerclass)) {
                ServiceLoader<java.security.Provider> sl =  ServiceLoader.load(Provider.class);
                for(Provider i: sl) {
                    //Don't reinsert myself
                    if (i instanceof SimpleProvider) {
                        continue;
                    }
                    try {
                        Security.insertProviderAt(i, Security.getProviders().length + 1);
                    } catch (Exception e) {
                        System.out.println("Failed to add " + i.getName() + " providers as a service: " + e.getMessage());
                    }
                }
            } else {
                //Don't reinsert myself
                if (SimpleProvider.class.getName().equals(providerclass)) {
                    return;
                }
                Security.insertProviderAt((Provider) Class.forName(providerclass).newInstance(), Security.getProviders().length + 1);
            }
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

}
