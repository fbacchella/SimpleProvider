package fr.jrds;

import java.security.Provider;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class SmartPkiProvider extends Provider {

    protected SmartPkiProvider() {
        super("SmartPki", 0.1, "A smart provider type");
        List<String> aliases = Collections.emptyList();
        Map<String,String> attributes = Collections.emptyMap();
        Service s = new Service(this, "KeyStore", "SPKI", SmartKeyStore.class.getCanonicalName(), aliases, attributes);
        putService(s);
    }

}
