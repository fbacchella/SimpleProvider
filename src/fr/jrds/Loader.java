package fr.jrds;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Loader {

    private static final String SECTION = "\\[(?<section>\\w+)\\]";
    private static final String PROVIDERCLASS = "(?<providerclass>(?:(?:[a-zA-Z_0-9]+\\.[a-zA-Z_0-9\\.]+)|services))";
    private static final String STORE = "(?<type>\\w+)(?::(?<password>.*?))?(?:=(?<path>.*?))?";

    private static final Pattern LINEPATTERN = Pattern.compile(String.format("^(?:(?:%s)|(?:%s)|(?:%s))?\\s*(?:#.*)?$", SECTION, PROVIDERCLASS, STORE));

    public enum MODE {
        STORES,
        PROVIDERS,
        NONE
    }
    
    @FunctionalInterface
    public interface Consumer {
        void apply(MODE mode, Matcher m);
    }


    public static void parse(InputStream stream, MODE expected, Consumer c) throws IOException, NoSuchAlgorithmException, CertificateException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
        String line;
        MODE mode = MODE.NONE;
        while ((line = reader.readLine()) !=null) {
            Matcher sectionMatch = LINEPATTERN.matcher(line);
            if( sectionMatch.matches()) {
                if (sectionMatch.group("section") != null) {
                    mode = MODE.valueOf(sectionMatch.group("section").toUpperCase());
                } else if (mode == expected) {
                    c.apply(mode, sectionMatch);
                }
            }
        }
    }

}
