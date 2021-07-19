package iehr.security;

import eu.interopehrate.security_commons.services.ca.CAServiceFactory;
import eu.interopehrate.security_commons.services.ca.api.CAService;
import iehr.security.api.CryptoManagement;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.concurrent.ExecutionException;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CryptoManagementImpl implements CryptoManagement {

    private static final String KEYSTORE_ALIAS = "ResearchCenter";
    private static final String KEYSTORE_PASSWORD = "interop";
    private static final String KEYSTORE_NAME = "keystore.p12";

    private final CAService ca;

    public CryptoManagementImpl(String caUrl) {
        ca = CAServiceFactory.create(caUrl);
    }


    @Override
    public PrivateKey getPrivateKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        char[] password = KEYSTORE_PASSWORD.toCharArray();
        KeyStore keyStore=KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(KEYSTORE_NAME),password);
        PrivateKey key = (PrivateKey)keyStore.getKey(KEYSTORE_ALIAS, password);
        return (PrivateKey) key;
    }

    @Override
    public RSAPublicKey getPublicKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        char[] password = KEYSTORE_PASSWORD.toCharArray();

        // Reload the keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(KEYSTORE_NAME), password);

        java.security.cert.Certificate cert = keyStore.getCertificate(KEYSTORE_ALIAS);
        RSAPublicKey pkey = (RSAPublicKey)cert.getPublicKey();
        return pkey;
    }

    //TODO: delete
    @Override
    public void fetchCertificate() {
        System.out.println("fetchCertificate-> CALLED");

        PrivateKey topPrivateKey = null;

        try{
            //Generate ROOT certificate
            CertAndKeyGen keyGen=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen.generate(1024);
            PrivateKey rootPrivateKey=keyGen.getPrivateKey();

            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 60 * 60);

            //Generate intermediate certificate
            CertAndKeyGen keyGen1=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen1.generate(1024);
            PrivateKey middlePrivateKey=keyGen1.getPrivateKey();

            X509Certificate middleCertificate = keyGen1.getSelfCertificate(new X500Name("CN=MIDDLE"), (long) 365 * 24 * 60 * 60);

            //Generate leaf certificate
            CertAndKeyGen keyGen2=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen2.generate(1024);
            topPrivateKey=keyGen2.getPrivateKey();

            X509Certificate topCertificate = keyGen2.getSelfCertificate(new X500Name("CN=TOP"), (long) 365 * 24 * 60 * 60);

            rootCertificate   = createSignedCertificate(rootCertificate,rootCertificate,rootPrivateKey);
            middleCertificate = createSignedCertificate(middleCertificate,rootCertificate,rootPrivateKey);
            topCertificate    = createSignedCertificate(topCertificate,middleCertificate,middlePrivateKey);

            X509Certificate[] chain = new X509Certificate[3];
            chain[0]=topCertificate;
            chain[1]=middleCertificate;
            chain[2]=rootCertificate;

            String alias = "mykey";
            char[] password = "password".toCharArray();
            String keystore = "keystore.jks";

            //Store the certificate chain
            storeKeyAndCertificateChain(alias, password, keystore, topPrivateKey, chain);
        }catch(Exception ex){
            ex.printStackTrace();
        }
    }

    //TODO: delete
    private static X509Certificate createSignedCertificate(X509Certificate cetrificate,X509Certificate issuerCertificate,PrivateKey issuerPrivateKey){
        try{
            Principal issuer = issuerCertificate.getSubjectDN();
            String issuerSigAlg = issuerCertificate.getSigAlgName();

            byte[] inCertBytes = cetrificate.getTBSCertificate();
            X509CertInfo info = new X509CertInfo(inCertBytes);
            info.set(X509CertInfo.ISSUER, issuer);

            //No need to add the BasicContraint for leaf cert
            if(!cetrificate.getSubjectDN().getName().equals("CN=TOP")){
                CertificateExtensions exts=new CertificateExtensions();
                BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
                exts.set(BasicConstraintsExtension.NAME,new BasicConstraintsExtension(false, bce.getExtensionValue()));
                info.set(X509CertInfo.EXTENSIONS, exts);
            }

            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);

            return outCert;
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return null;
    }

    //TODO: delete
    private static void storeKeyAndCertificateChain(String alias, char[] password, String keystore, Key key, X509Certificate[] chain) throws Exception{
        KeyStore keyStore=KeyStore.getInstance("jks");
        keyStore.load(null,null);
        keyStore.setKeyEntry(alias, key, password, chain);
        keyStore.store(new FileOutputStream(keystore),password);
    }

    @Override
    public String signPayload(String payload, PrivateKey privateKey) throws InvalidKeyException, SignatureException {
            Signature privateSignature = null;
            try {
                privateSignature = Signature.getInstance("SHA256withRSA");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            privateSignature.initSign(privateKey);
            privateSignature.update(payload.getBytes(UTF_8));
            byte[] signature = privateSignature.sign();

            return Base64.getEncoder().encodeToString(signature);
    }

    @Override
    public boolean verifyPayload(RSAPublicKey publicKey, byte[] payload, byte[] sign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            byte[] signedPayloadContent = Base64.getDecoder().decode(sign);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(payload);
            boolean result = signature.verify(signedPayloadContent);
            System.out.println("MSSG verifySignature -> " + String.valueOf(result));
            return result;
    }

    @Override
    public byte[] getUserCertificate(String userAlias) throws IOException, ExecutionException, InterruptedException {
        return ca.getUserCertificate(userAlias);
    }

    @Override
    public Boolean validateUserCertificate(byte[] certificateData) throws IOException, ExecutionException, InterruptedException {
        return ca.validateUserCertificate(certificateData);
    }

}
