package iehr.security.dummy;

import iehr.security.ConsentManagementFactory;
import iehr.security.CryptoManagementFactory;
import iehr.security.api.ConsentManagement;
import iehr.security.api.CryptoManagement;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

public class Main {

    public static final String CA_URL = "http://212.101.173.84:8071";

    public static void main(String[] args) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, SignatureException, InvalidKeyException {
        ConsentManagement consentManagement = ConsentManagementFactory.create();

        String consent = consentManagement.generateConsent();

        CryptoManagement cryptoManagement = CryptoManagementFactory.create(CA_URL);

        File f = new File("keystore.p12");
        if (!(f.isFile() && f.canRead())) {
            System.out.println("DON NOT EXIST -> FETCH");
        }

        PrivateKey privateKey = cryptoManagement.getPrivateKey();
        RSAPublicKey rsaPublicKey = cryptoManagement.getPublicKey();

        String payload = consent;
        String signed = cryptoManagement.signPayload(payload,privateKey);
        Boolean verify = cryptoManagement.verifyPayload(rsaPublicKey,payload.getBytes(), signed.getBytes());

        System.out.println("Sign " + signed);
        System.out.println("Verify " + verify);
    }

}