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
