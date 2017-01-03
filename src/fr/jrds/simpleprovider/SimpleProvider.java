package fr.jrds.simpleprovider;

import java.security.Provider;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class SimpleProvider extends Provider {
    
    public static final String NAME = "MKS";

    protected SimpleProvider() {
        super("SmartPki", 0.1, "A simple provider type");
        List<String> aliases = Collections.emptyList();
        Map<String,String> attributes = Collections.emptyMap();
        Service s = new Service(this, "KeyStore", NAME, MultiKeyStore.class.getCanonicalName(), aliases, attributes);
        putService(s);
    }

}
