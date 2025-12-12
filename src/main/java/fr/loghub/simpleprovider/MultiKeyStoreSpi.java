package fr.loghub.simpleprovider;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.io.*;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.ByteBuffer;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MultiKeyStoreSpi extends KeyStoreSpi {

    private static final Map<String, KeyFactory> kfmap = new ConcurrentHashMap<>();
    private final List<KeyStore> stores = new ArrayList<>();

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

    private static final String DEFAULT_ALIAS = "__default_alias__";
    public static final KeyStore.ProtectionParameter EMPTYPROTECTION = new KeyStore.PasswordProtection(new char[] {});

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

    public MultiKeyStoreSpi() {
        try {
            // An empty initial trust store, for loaded PEM
            KeyStore first = KeyStore.getInstance("JKS");
            first.load(null, null);
            stores.add(first);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new IllegalStateException("Missing security algorithms", e);
        }
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        for (KeyStore ks: stores) {
            try {
                Key val = ks.getKey(alias, password);
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
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
        throw new UnsupportedOperationException("Read-only key store");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
        throw new UnsupportedOperationException("Read-only key store");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) {
        throw new UnsupportedOperationException("Read-only key store");
    }

    @Override
    public void engineDeleteEntry(String alias) {
        throw new UnsupportedOperationException("Read-only key store");
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
        int kssize;
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

    private Enumeration<String> findNext(Enumeration<String> enumerator, Iterator<KeyStore> iter) {
        while (enumerator == null || ! enumerator.hasMoreElements()) {
            KeyStore cur = findNonEmpty(iter);
            // The last keystore found was empty or no more to try, keystore enumeration is finished
            if (cur == null) {
                enumerator = null;
                break;
            }
            try {
                enumerator = cur.aliases();
            } catch (KeyStoreException e) {
                // This keystore is broken, just skip it
            }
        }
        return enumerator;
    }

    @Override
    public Enumeration<String> engineAliases() {
        Iterator<KeyStore> iter = stores.iterator();

        return new Enumeration<>() {
            private Enumeration<String> enumerator = findNext(null, iter);

            @Override
            public boolean hasMoreElements() {
                enumerator = findNext(enumerator, iter);
                // If was unable to find a valid new enumerator, enumeration is finished
                return enumerator != null;
            }

            @Override
            public String nextElement() {
                if (enumerator == null) {
                    throw new NoSuchElementException();
                } else {
                    return enumerator.nextElement();
                }
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
    public void engineStore(OutputStream stream, char[] password) {
        throw new UnsupportedOperationException("Non persistent key store");
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        Loader.Consumer c = (Loader.MODE mode, Matcher sectionMatch) -> {
            if (sectionMatch.group("type") != null) {
                String storePassword = Optional.of(sectionMatch.group("password")).orElse("");
                Path storePath = Path.of(sectionMatch.group("path"));
                addStore(sectionMatch.group("type"), storePath, Map.of("password", storePassword));
            }
        };
        Loader.parse(stream, Loader.MODE.STORES, c);
    }

    private void addStore(String type, Path path, Map<String, Object> fileParams) {
        try {
            switch (type.toLowerCase(Locale.ROOT)) {
                case "system"     -> loadSystemStores();
                case "default"    -> loadJvmDefault();
                case "pem"        -> loadPem(path, Map.of());
                case "p12", "pfx" -> loadKeystore("PKCS12", path, fileParams);
                case "jks"        -> loadKeystore("JKS", path, fileParams);
                case "jceks"      -> loadKeystore("JCEKS", path, fileParams);
                case "bks"        -> loadKeystore("BKS", path, fileParams);
                case "ubr"        -> loadKeystore("Keystore.UBER", path, fileParams);
            }
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    private void loadSystemStores() throws GeneralSecurityException, IOException {
        String operatingSystem = System.getProperty("os.name", "");
        String[] systemStores = new String[] {};

        if (operatingSystem.startsWith("Mac") && Runtime.version().feature() >= 23) {
            systemStores = new String[] {"KeychainStore", "KeychainStore-ROOT"};
        } else if (operatingSystem.startsWith("Mac")) {
            systemStores = new String[] {"KeychainStore"};
        } else if (operatingSystem.startsWith("Windows")) {
            systemStores = new String[] {"Windows-MY", "Windows-ROOT"};
        } else if (operatingSystem.startsWith("Linux")) {
            // Paths where linux might store certs
            for (String certsPath : new String[]{
                    "/etc/ssl/certs/ca-certificates.crt",
                    "/etc/pki/tls/cert.pem",
                    "/etc/ssl/cert.pem",
                    "/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt",
                    "/usr/share/pki/ca-trust-legacy/ca-bundle.legacy.default.crt",
            }) {
                if (Files.isReadable(Paths.get(certsPath))) {
                    loadPem(Paths.get(certsPath), Collections.emptyMap());
                    break;
                }
            }
        }
        for (String n : systemStores) {
            KeyStore ks = KeyStore.getInstance(n);
            ks.load(null, "".toCharArray());
            stores.add(ks);
        }
    }

    private void loadJvmDefault() throws GeneralSecurityException, IOException {
        String[] paths = new String[]{
                System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "jssecacerts",
                System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts"
        };
        for (String storePathName : paths) {
            Path storePath = Paths.get(storePathName);
            if (Files.exists(storePath)) {
                KeyStore ks = KeyStore.getInstance("jks");
                InputStream is = new FileInputStream(storePathName);
                ks.load(is, null);
                stores.add(ks);
                break;
            }
        }
    }

    private void loadKeystore(String type, Path path, Map<String, Object> fileParams) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance(type);
        String password = (String) fileParams.getOrDefault("password", "");
        try (InputStream is = Files.newInputStream(path)) {
            ks.load(is, password.toCharArray());
            stores.add(ks);
        }
    }

    /**
     * Two kind of PEM files are expected:
     * <ul>
     *     <li>A list of certificates, they are imported as separated certificates entries.</li>
     *     <li>A private key, and one or more certificates. It’s used a certificate chain and are added as a single entry.</li>
     * </ul>
     * If no alias is provided for the secret key, the first value of the dn for the leaf certificate will be used.
     * @param path the URI to the pem file
     * @param fileParams some parameters, it can contain the alias that will be used for the secret key.
     * @throws CertificateException
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws KeyStoreException
     */
    private void loadPem(Path path, Map<String, Object> fileParams) throws IOException, GeneralSecurityException {
        List<Certificate> certs = new ArrayList<>(1);
        PrivateKey key = null;
        try (BufferedReader br = Files.newBufferedReader(path)) {
            String line;
            StringBuilder buffer = new StringBuilder();
            while ((line = br.readLine()) != null) {
                Matcher matcher = MARKERS.matcher(line);
                matcher.matches();
                if (matcher.group("begin") != null) {
                    buffer.setLength(0);
                } else if (matcher.group("end") != null) {
                    byte[] content = decoder.decode(buffer.toString());
                    digest.reset();
                    if (matcher.group("cert") != null) {
                        certs.add(cf.generateCertificate(new ByteArrayInputStream(content)));
                    } else if (matcher.group("prk") != null ||
                            matcher.group("rprk") != null ||
                            matcher.group("epk") != null) {
                        if (key != null) {
                            throw new IllegalArgumentException("Multiple key in a PEM");
                        }
                        if (matcher.group("rprk") != null) {
                            content = convertPkcs1(content);
                        }
                        if (matcher.group("epk") != null) {
                            content = decrypteEncryptedPkcs8(content, fileParams.getOrDefault("password", "").toString());
                        }
                        PKCS8Codec codec = new PKCS8Codec(ByteBuffer.wrap(content));
                        codec.read();
                        PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(content);
                        key = kfmap.computeIfAbsent(codec.getAlgo(), this::resolveFactory).generatePrivate(keyspec);
                    } else {
                        throw new IllegalArgumentException("Unknown entry type in PEM");
                    }
                } else {
                    buffer.append(line);
                }
            }
            addEntry(certs, key, fileParams);
        }
    }

    private KeyFactory resolveFactory(String protocol) {
        try {
            return KeyFactory.getInstance(protocol);
        } catch (NoSuchAlgorithmException ex) {
            throw new UndeclaredThrowableException(ex);
        }
    }

    /**
     * Wrap PKCS#1 bytes as a PCKS1#8 buffer by prefixing with the right header
     * @param pkcs1Bytes
     * @return
     */
    private byte[] convertPkcs1(byte[] pkcs1Bytes) {
        int pkcs1Length = pkcs1Bytes.length;
        int totalLength = pkcs1Length + 22;
        int bufferLength = totalLength + 4;
        byte[] pkcs8Header = new byte[] {
                0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff), (byte) (totalLength & 0xff), // Sequence + total length
                0x2, 0x1, 0x0, // Integer (0)
                0x30, 0xD, 0x6, 0x9, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0xD, 0x1, 0x1, 0x1, 0x5, 0x0, // Sequence: 1.2.840.113549.1.1.1, NULL
                0x4, (byte) 0x82, (byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff) // Octet string + length
        };
        byte[] pkcs8bytes = new byte[bufferLength];
        ByteBuffer pkcs8buffer = ByteBuffer.wrap(pkcs8bytes);
        pkcs8buffer.put(pkcs8Header);
        pkcs8buffer.put(pkcs1Bytes);
        return pkcs8bytes;
    }

    private void addEntry(List<Certificate> certs, PrivateKey key, Map<String, Object> params) throws KeyStoreException {
        if (certs.isEmpty()) {
            throw new IllegalArgumentException("No certificates to store");
        }
        String alias = (String) params.get("alias");
        if (alias == null) {
            Iterator<Certificate> iter = certs.iterator();
            Certificate leaf = null;
            while (iter.hasNext()) {
                Certificate cert = iter.next();
                if ("X.509".equals(cert.getType())) {
                    X509Certificate x509cert = (X509Certificate) cert;
                    if (x509cert.getBasicConstraints() == -1) {
                        // The leaf certificate
                        leaf = cert;
                        iter.remove();
                        break;
                    }
                }
            }
            if (leaf != null) {
                alias = resolveAlias(leaf, params);
                // Ensure that the leaf certificate is the first
                certs.add(0, leaf);
            }
        }
        if (alias == null) {
            alias = (String) params.get(DEFAULT_ALIAS);
        }
        if (key != null && stores.get(0).containsAlias(alias)) {
            // If object already seen, don't add it again
        } else if (key != null) {
            KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(key, certs.stream().toArray(Certificate[]::new));
            stores.get(0).setEntry(alias, entry, EMPTYPROTECTION);
        } else {
            for (Certificate cert : certs) {
                String certAlias = resolveAlias(cert, params);
                KeyStore.TrustedCertificateEntry entry = new KeyStore.TrustedCertificateEntry(cert);
                stores.get(0).setEntry(certAlias, entry, null);
            }
        }
    }

    private String resolveAlias(Certificate cert, Map<String, Object> params) {
        String certalias = null;
        if ("X.509".equals(cert.getType())) {
            X509Certificate x509cert = (X509Certificate) cert;
            try {
                LdapName ldapDN = new LdapName(x509cert.getSubjectX500Principal().getName());
                // Order of values are inversed between LDAP and X.509, so get the last one.
                certalias = ldapDN.getRdn(ldapDN.size() - 1).getValue().toString();
            } catch (InvalidNameException e) {
            }
        }
        return  certalias;
    }

    private byte[] decrypteEncryptedPkcs8(byte[] epk, String password)
            throws IOException, GeneralSecurityException {
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(epk);

        String encAlg = epki.getAlgName();

        AlgorithmParameters encAlgParams = epki.getAlgParameters();
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(encAlg);
        SecretKey pbeKey = keyFact.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(encAlg);

        cipher.init(Cipher.DECRYPT_MODE, pbeKey, encAlgParams);
        PKCS8EncodedKeySpec privateKeySpec = epki.getKeySpec(cipher);

        return privateKeySpec.getEncoded();
    }

}
