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
        System.out.println("Check if user certificate is valid: "+ isValid);
        X509Certificate certificate = cryptoManagement.toX509Certificate(certificateData);
        RSAPublicKey rsaPublicKey = (RSAPublicKey)certificate.getPublicKey();
        Boolean verify = cryptoManagement.verifyPayload(rsaPublicKey,consent.getBytes(), signed.getBytes());
        System.out.println("Verify Payload: " + verify);
        PrivateKey researchPrivateKey = cryptoManagement.getPrivateKey();
        String researchSigned = cryptoManagement.signPayload(consent,researchPrivateKey);
        System.out.println("Sign " + researchSigned);
        byte[] researchCertificateData = cryptoManagement.getUserCertificate("research");
        // send researchSigned and researchCertificateData to mobile app


        // Mobile app
        Boolean isReasearchCertificateValid = cryptoManagement.validateUserCertificate(researchCertificateData);
        System.out.println("Check if research certificate is valid: "+ isReasearchCertificateValid);
        X509Certificate researchCertificate = cryptoManagement.toX509Certificate(researchCertificateData);
        RSAPublicKey rsaResearchPublicKey = (RSAPublicKey)researchCertificate.getPublicKey();
        Boolean researchVerify = cryptoManagement.verifyPayload(rsaResearchPublicKey,consent.getBytes(), researchSigned.getBytes());
        System.out.println("Verify Payload: " + researchVerify);

    }

    private static void diffieHellman() throws Exception {
        CryptoManagement crypto = CryptoManagementFactory.create(CA_URL);

        //Mobile app
        KeyPair mobileKpair = crypto.aliceInitKeyPair();
        KeyAgreement mobileKpairKA = crypto.aliceKeyAgreement(mobileKpair);
        byte[] mobilePubKeyEnc = crypto.alicePubKeyEnc(mobileKpair);
        // send mobilePubKeyEnc to research center..

        //Research Center
        KeyPair researchkeypair = crypto.bobInitKeyPair(mobilePubKeyEnc);
        KeyAgreement researchKeyAgreement = crypto.bobKeyAgreement(researchkeypair);
        KeyAgreement symkeyagreement = crypto.bobKeyAgreementFin(mobilePubKeyEnc, researchKeyAgreement);
        byte[] researchSharedSecret = symkeyagreement.generateSecret();
        SecretKeySpec symkeyspec = crypto.generateSymmtericKey(researchSharedSecret, 32);
        String symkeys = Base64.getEncoder().encodeToString(symkeyspec.getEncoded()).replaceAll("\r", "").replaceAll("\n", "");
        System.out.println("Research center symkey: " + symkeys);
        byte[] researchPubKeyEnc = crypto.bobPubKeyEnc(researchkeypair);
        // send researchPubKeyEnc to mobile app

        //Mobile app
        KeyAgreement mobileSymkeyagreement = crypto.aliceKeyAgreementFin(researchPubKeyEnc,mobileKpairKA);
        byte[] mobileSharedSecret = mobileSymkeyagreement.generateSecret();
        SecretKeySpec mobileSymkeyspec = crypto.generateSymmtericKey(mobileSharedSecret,32);
        String symkeystr = Base64.getEncoder().encodeToString(mobileSymkeyspec.getEncoded());
        System.out.println("Mobile app symkey: " + symkeystr);


        //Mobile app
        String encrypted = crypto.encrypt("sofianna", symkeystr);
        // send encrypted to research center

        //Research Center
        String decrypted = crypto.decrypt(encrypted, symkeys);
        System.out.println("Decrypted: "+decrypted);

    }

    public static void main(String[] args) throws Exception {
        consent();
        diffieHellman();
    }


}