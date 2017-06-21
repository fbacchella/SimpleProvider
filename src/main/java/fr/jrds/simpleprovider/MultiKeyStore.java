package fr.jrds.simpleprovider;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MultiKeyStore extends KeyStoreSpi {

    private final List<KeyStore> stores = new ArrayList<>();
    {
        try {
            // An empty initial trust store, for loaded PEM
            KeyStore first = KeyStore.getInstance("JKS");
            first.load(null, null);
            stores.add(first);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    static private final CertificateFactory cf;
    static private final MessageDigest digest;
    static {
        try {
            cf = CertificateFactory.getInstance("X.509");
            digest = MessageDigest.getInstance("MD5");
        } catch (CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


    private static final Pattern MARKERS;
    static {
        String rkey = "(?<rkey>PRIVATE KEY)";
        String ukey = "(?<ukey>PUBLIC KEY)";
        String cert = "(?<cert>CERTIFICATE)";
        String epk = "(?<epk>ENCRYPTED PRIVATE KEY)";
        String begin = String.format("(?<begin>-+BEGIN .*-+)");
        String end = String.format("(?<end>-+END (?:%s|%s|%s|%s)-+)", rkey, ukey, cert, epk);
        MARKERS = Pattern.compile(String.format("(?:%s)|(?:%s)|.*?", begin, end));
    }
    Base64.Decoder decoder = Base64.getDecoder();
    Base64.Encoder encoder = Base64.getEncoder();

    public MultiKeyStore() {
        super();

    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        for( KeyStore ks: stores) {
            try {
                Key val = ks.getKey(alias, password);
                if (val != null) {
                    return val;
                }
            } catch (KeyStoreException e) {
            }
        }
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        for( KeyStore ks: stores) {
            try {
                Certificate[] val = ks.getCertificateChain(alias);
                if (val != null) {
                    return val;
                }
            } catch (KeyStoreException e) {
            }
        }
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        for( KeyStore ks: stores) {
            try {
                Certificate val = ks.getCertificate(alias);
                if (val != null) {
                    return val;
                }
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        for( KeyStore ks: stores) {
            try {
                Date val = ks.getCreationDate(alias);
                if (val != null) {
                    return val;
                }
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        System.out.println("engineSetKeyEntry");

    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        System.out.println("engineSetKeyEntry");

    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        System.out.println("engineSetCertificateEntry");

    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        for( KeyStore ks: stores) {
            try {
                if (ks.containsAlias(alias)) {
                    ks.deleteEntry(alias);
                }
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
    }

    /**
     * Find the first not empty Keystore extracted from the iterator
     * @param iter
     * @return a Keystore or null if no more iterator to check
     */
    private KeyStore findNonEmpty(Iterator<KeyStore> iter) {
        KeyStore totry = null;
        // The aliases enumerator is not usable (empty or null), find the next one
        // Find the next non empty KeyStore
        int kssize = 0;
        while(iter.hasNext()) {
            totry = iter.next();
            try {
                kssize = totry.size();
                if (kssize != 0) {
                    break;
                } else {
                    totry = null;
                }
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
        return totry;
    }

    @Override
    public Enumeration<String> engineAliases() {
        final Iterator<KeyStore> iter = stores.iterator();
        return new Enumeration<String>(){
            //private KeyStore cur = null;
            private Enumeration<String> enumerator = null;
            @Override
            public boolean hasMoreElements() {
                // The current enumerator is empty or non valid, looking for the next one
                while (enumerator == null || ! enumerator.hasMoreElements()) {
                    // drop old enumerator
                    enumerator = null;
                    KeyStore cur = findNonEmpty(iter);
                    // The last keystore found was empty or no more to try, keystore enumeration is finished
                    if (cur == null) {
                        break;
                    }
                    try {
                        enumerator = cur.aliases();
                    } catch (KeyStoreException e) {
                        // This keystore is broken, just skip it
                    }
                }
                // If was unable to find a valid new enumerator, enumeration is finished
                return enumerator != null;
            }

            @Override
            public String nextElement() {
                return enumerator.nextElement();
            }

        };
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        for( KeyStore ks: stores) {
            try {
                boolean val = ks.containsAlias(alias);
                if (val) {
                    return val;
                }
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
        return false;
    }

    @Override
    public int engineSize() {
        int size = 0;
        for(KeyStore ks: stores) {
            try {
                size += ks.size();
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
        return size;
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        for(KeyStore ks: stores) {
            try {
                boolean val = ks.isKeyEntry(alias);
                if (val) {
                    return val;
                }
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        for(KeyStore ks: stores) {
            try {
                boolean val = ks.isCertificateEntry(alias);
                if (val) {
                    return val;
                }
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        for(KeyStore ks: stores) {
            try {
                String val = ks.getCertificateAlias(cert);
                if (val != null) {
                    return val;
                }
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        System.out.println("engineStore");
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        Loader.Consumer c = (Loader.MODE mode, Matcher sectionMatch) -> {
            if (sectionMatch.group("type") != null) {
                addStore(sectionMatch.group("type"), sectionMatch.group("password"), sectionMatch.group("path"));
            }
        };
        Loader.parse(stream, Loader.MODE.STORES, c);
    }

    private void addStore(String type, String password, String path) {
        if (password == null) {
            password = "";
        }
        try {
            if("system".equals(type)) {
                String operatingSystem = System.getProperty("os.name", "");
                KeyStore systemks = null;
                if (operatingSystem.startsWith("Mac")) {
                    systemks = KeyStore.getInstance("KeychainStore");
                } else if (operatingSystem.startsWith("Windows")){
                    systemks = KeyStore.getInstance("Windows-ROOT");
                }
                if (systemks != null) {
                    systemks.load(null, password.toCharArray());
                    stores.add(systemks);
                }
            } else if ("default".equals(type)) {
                String[] paths = new String[] {
                        System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "jssecacerts",
                        System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts"
                };
                for (String storePathName: paths) {
                    Path storePath = Paths.get(storePathName);
                    if (Files.exists(storePath)) {
                        KeyStore ks = KeyStore.getInstance("jks");
                        InputStream is = new FileInputStream(storePathName);
                        ks.load(is, null);
                        stores.add(ks);
                        break;
                    }
                }
            } else if ("pem".equals(type.toLowerCase())) {
                loadPem(path);
            } else {
                KeyStore ks = KeyStore.getInstance(type);
                InputStream is = new FileInputStream(path);
                ks.load(is, password.toCharArray());
                stores.add(ks);
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
    }

    private void loadPem(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            StringBuilder buffer = new StringBuilder();
            while ((line = br.readLine()) != null) {
                Matcher matcher = MARKERS.matcher(line);
                matcher.matches();
                if (matcher.group("begin") != null) {
                    buffer.setLength(0);
                } else if (matcher.group("end") != null){
                    try {
                        byte[] content = decoder.decode(buffer.toString());
                        String alias = encoder.encodeToString(digest.digest(content));
                        // If object already seen, don't add it again
                        if (stores.get(0).containsAlias(alias)) {
                            continue;
                        }
                        if (matcher.group("cert") != null) {
                            Certificate cert = cf.generateCertificate(new ByteArrayInputStream(content));
                            KeyStore.TrustedCertificateEntry entry = new KeyStore.TrustedCertificateEntry(cert);
                            digest.reset();
                            stores.get(0).setEntry(alias, entry, null);
                        }
                    } catch (CertificateException e) {
                        e.printStackTrace();
                    } catch (KeyStoreException e) {
                        e.printStackTrace();
                    }
                } else {
                    buffer.append(line);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

}
