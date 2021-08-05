package iehr.security.dummy;

import iehr.security.ConsentManagementFactory;
import iehr.security.CryptoManagementFactory;
import iehr.security.api.ConsentManagement;
import iehr.security.api.CryptoManagement;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.concurrent.ExecutionException;

public class Main {

    public static final String CA_URL = "http://212.101.173.84:8071";


    private static void consent() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, SignatureException, InvalidKeyException, ExecutionException, InterruptedException {
        ConsentManagement consentManagement = ConsentManagementFactory.create();
        CryptoManagement cryptoManagement = CryptoManagementFactory.create(CA_URL);

        // mobile app
        String consent = consentManagement.generateConsent();
        PrivateKey privateKey = cryptoManagement.getPrivateKey();
        String signed = cryptoManagement.signPayload(consent,privateKey);
        System.out.println("Sign " + signed);
        byte[] certificateData = cryptoManagement.getUserCertificate("research");
        // send signed, consent and certificateData to research center...

        // Research center
        Boolean isValid = cryptoManagement.validateUserCertificate(certificateData);
        if(isValid) {
            X509Certificate certificate = cryptoManagement.toX509Certificate(certificateData);
            RSAPublicKey rsaPublicKey = (RSAPublicKey)certificate.getPublicKey();
            Boolean verify = cryptoManagement.verifyPayload(rsaPublicKey,consent.getBytes(), signed.getBytes());
            System.out.println("Verify " + verify);
        }
        else {
            System.out.println("Certificate is not valid");
        }
    }

    private static void diffieHellman() throws Exception {
        CryptoManagement crypto = CryptoManagementFactory.create(CA_URL);

        //Research center
        KeyPair researchKpair = crypto.aliceInitKeyPair();
        KeyAgreement researchKpairKA = crypto.aliceKeyAgreement(researchKpair);
        byte[] alicePubKeyEnc = crypto.alicePubKeyEnc(researchKpair);
        // send alicePubKeyEnc to mobile app..

        PublicKey alicePubKey = researchKpair.getPublic();

        //Mobile app
        KeyPair mobilekeypair = crypto.bobInitKeyPair(alicePubKeyEnc);
        KeyAgreement mobileKeyAgreement = crypto.bobKeyAgreement(mobilekeypair);
        KeyAgreement symkeyagreement = crypto.bobKeyAgreementFin(alicePubKey, mobileKeyAgreement);
        byte[] mobileSharedSecret = symkeyagreement.generateSecret();
        SecretKeySpec symkeyspec = crypto.generateSymmtericKey(mobileSharedSecret, 32);
        String symkeys = Base64.getEncoder().encodeToString(symkeyspec.getEncoded()).replaceAll("\r", "").replaceAll("\n", "");
        System.out.println("Mobile app symkey: " + symkeys);
        byte[] mobilePubKeyEnc = crypto.bobPubKeyEnc(mobilekeypair);
        // send mobilePubKeyEnc to research center

        //Research center
        KeyAgreement aliceSymkeyagreement = crypto.aliceKeyAgreementFin(mobilePubKeyEnc,researchKpairKA);
        byte[] aliceSharedSecret = aliceSymkeyagreement.generateSecret();
        SecretKeySpec aliceSymkeyspec = crypto.generateSymmtericKey(aliceSharedSecret,32);
        String symkeystr = Base64.getEncoder().encodeToString(aliceSymkeyspec.getEncoded());
        System.out.println("Research Center symkey: " + symkeystr);
    }

    public static void main(String[] args) throws Exception {
        consent();
        diffieHellman();
    }


}