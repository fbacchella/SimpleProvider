package fr.jrds.simpleprovider;

import java.security.Provider;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class SimpleProvider extends Provider {
    
    public static final String NAME = "Simple";

    private static final Map<String, String> SERVICES = Map.of(
            "KeyStore", MultiKeyStore.class.getCanonicalName(),
            "KeyManagerFactory", SmartKeyManagerFactorySpi.class.getCanonicalName()
    );

    public SimpleProvider() {
        super("SimpleProvider", 0.1, "A simple provider to automatize handling");
        List<String> aliases = Collections.emptyList();
        Map<String,String> attributes = Collections.emptyMap();
        SERVICES.forEach((n, c) -> putService(new Service(this, n, NAME, c, aliases, attributes)));
    }

}
