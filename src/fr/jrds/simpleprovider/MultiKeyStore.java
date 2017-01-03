package fr.jrds.simpleprovider;

import java.io.File;
import java.io.FileInputStream;
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
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;

public class MultiKeyStore extends KeyStoreSpi {

    private final List<KeyStore> stores = new ArrayList<>();

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
            }
        }
    }

    @Override
    public Enumeration<String> engineAliases() {
        final Iterator<KeyStore> iter = stores.iterator();
        return new Enumeration<String>(){
            private KeyStore cur = iter.hasNext() ? iter.next() : null;
            private Enumeration<String> enumerator = null;
            @Override
            public boolean hasMoreElements() {
                if (cur == null) {
                    return false;
                }
                while (enumerator == null || ! enumerator.hasMoreElements()) {
                    // The enumerator is not usable (empty or null), find the next one
                    try {
                        if (enumerator == null) {
                            enumerator = cur.aliases();
                            if (enumerator.hasMoreElements()) {
                                break;
                            } else { 
                                if (iter.hasNext()) {
                                    cur = iter.next();
                                } else {
                                    return false;
                                }
                            }
                        } else {
                            enumerator = null;
                            if (iter.hasNext()) {
                                cur = iter.next();
                            } else {
                                return false;
                            }
                        }
                    } catch (KeyStoreException e) {
                        if (iter.hasNext()) {
                            cur = iter.next();
                        } else {
                            return false;
                        }
                    }
                }
                return true;
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
                    systemks = KeyStore.getInstance("Windows-MY");
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

}
