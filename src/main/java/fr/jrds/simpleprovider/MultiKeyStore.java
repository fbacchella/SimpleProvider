package fr.jrds.simpleprovider;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
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
    private static final KeyFactory kf;
    static private final MessageDigest digest;
    static {
        try {
            cf = CertificateFactory.getInstance("X.509");
            digest = MessageDigest.getInstance("MD5");
            kf = KeyFactory.getInstance("RSA");
        } catch (CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


    private static final Pattern MARKERS;
    static {
        String privateKey = "(?<prk>PRIVATE KEY)";
        String rsakey = "(?<rprk>RSA PRIVATE KEY)";
        String pubKey = "(?<puk>PUBLIC KEY)";
        String cert = "(?<cert>CERTIFICATE)";
        String epk = "(?<epk>ENCRYPTED PRIVATE KEY)";
        String begin = "(?<begin>-+BEGIN .*-+)";
        String end = String.format("(?<end>-+END (?:%s|%s|%s|%s|%s)-+)", privateKey, rsakey, pubKey, cert, epk);
        MARKERS = Pattern.compile(String.format("(?:%s)|(?:%s)|.*?", begin, end));
    }
    private static final Base64.Decoder decoder = Base64.getDecoder();
    private static final Base64.Encoder encoder = Base64.getEncoder();

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        for (KeyStore ks: stores) {
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
        for (KeyStore ks: stores) {
            try {
                Certificate[] val = ks.getCertificateChain(alias);
                if (val != null) {
                    return val;
                }
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
        return new Certificate[] {};
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        for (KeyStore ks: stores) {
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
        for (KeyStore ks: stores) {
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
        throw new UnsupportedOperationException("Read-only key store");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException("Read-only key store");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new UnsupportedOperationException("Read-only key store");
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
        throw new UnsupportedOperationException("Read-only key store");
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
        Certificate cert = null;
        PrivateKey key = null;
        String alias = encoder.encodeToString(filename.getBytes());
        int count = 0;
        try (BufferedReader br = Files.newBufferedReader(Paths.get(filename), StandardCharsets.UTF_8)) {
            String line;
            StringBuilder buffer = new StringBuilder();
            while ((line = br.readLine()) != null) {
                Matcher matcher = MARKERS.matcher(line);
                matcher.matches();
                if (matcher.group("begin") != null) {
                    count++;
                    buffer.setLength(0);
                } else if (matcher.group("end") != null){
                    byte[] content = decoder.decode(buffer.toString());
                    digest.reset();
                    if (matcher.group("cert") != null) {
                        if (cert != null) {
                            addEntry(alias + "_" + count, cert, key);
                            cert = null;
                            key = null;
                        }
                        cert = cf.generateCertificate(new ByteArrayInputStream(content));
                    } else if (matcher.group("prk") != null){
                        if (key != null) {
                            throw new IllegalStateException("Multiple key in a PEM file" + filename);
                        }
                        PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(content);
                        key = kf.generatePrivate(keyspec);
                        // If not cert found, the key will be save at the next entry, hopfully a cert
                        if (cert != null) {
                            addEntry(alias + count, cert, key);
                            cert = null;
                            key = null;
                        }
                    } else {
                        throw new IllegalArgumentException("Unknown PEM entry in file " + filename);
                    }
                } else {
                    buffer.append(line);
                }
            }
            // trying to load last entry
            addEntry(alias, cert, key);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid PEM file " + filename, e);
        } catch (CertificateException | KeyStoreException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid PEM entry in file " + filename, e);
        }
    }

    private void addEntry(String alias, Certificate cert, PrivateKey key) throws KeyStoreException {
        if (cert != null && "X.509".equals(cert.getType())) {
            X509Certificate x509cert = (X509Certificate) cert;
            alias = x509cert.getSubjectX500Principal().getName();
        }
        if (cert == null) {
            // No certificate found to import
        } else if (stores.get(0).containsAlias(alias)) {
            // If object already seen, don't add it again
        } else  if (key != null) {
            KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(key, new Certificate[] {cert});
            stores.get(0).setEntry(alias, entry, new KeyStore.PasswordProtection(new char[] {}));
        } else {
            KeyStore.TrustedCertificateEntry entry = new KeyStore.TrustedCertificateEntry(cert);
            stores.get(0).setEntry(alias, entry, null);
        }
    }

}
