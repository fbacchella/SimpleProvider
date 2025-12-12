package fr.loghub.simpleprovider;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class AutoCA {
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String dn)
            throws OperatorCreationException, CertificateException
    {
        X500Name subject = new X500Name(dn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60);
        Date notAfter = new Date(System.currentTimeMillis() + (3650L * 24 * 60 * 60 * 1000));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter,
                subject, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    public static X509Certificate generateServerCertificate(
            KeyPair serverKeyPair, X509Certificate caCert,
            PrivateKey caPrivateKey, String dn, Object... altNames
    ) throws CertIOException, OperatorCreationException, CertificateException
    {

        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(dn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60);
        Date notAfter = new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter,
                subject, serverKeyPair.getPublic());

        if (altNames.length != 0) {
            List<GeneralName> names = new ArrayList<>(altNames.length);
            for (Object altName : altNames) {
                if (altName instanceof InetAddress) {
                    InetAddress ia = (InetAddress) altName;
                    names.add(new GeneralName(GeneralName.iPAddress, ia.getHostAddress()));
                    names.add(new GeneralName(GeneralName.dNSName, ia.getHostName()));
                } else if (altName instanceof String) {
                    names.add(new GeneralName(GeneralName.dNSName, (String) altName));
                } else {
                    names.add(GeneralName.getInstance(altName));
                }
            }
            GeneralNames subjectAltNames = new GeneralNames(names.toArray(GeneralName[]::new));
            certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    public static KeyStore getKeyStore(String dn, Object... altNames)
            throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException,
                           KeyStoreException
    {
        KeyPair caKeyPair = generateKeyPair();
        X509Certificate caCert = generateSelfSignedCertificate(caKeyPair, "CN=loghub");

        KeyPair hostKeyPair = generateKeyPair();
        X509Certificate hostCert = generateServerCertificate(hostKeyPair, caCert, caKeyPair.getPrivate(), dn, altNames);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        X509Certificate[] chain = new X509Certificate[] { hostCert, caCert };

        keyStore.setKeyEntry("server", hostKeyPair.getPrivate(), "".toCharArray(), chain);
        keyStore.setCertificateEntry("ca", caCert);
        return keyStore;
    }

    public static SSLContext createSSLContext(KeyStore keyStore)
            throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, KeyManagementException
    {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        return sslContext;
    }
}
