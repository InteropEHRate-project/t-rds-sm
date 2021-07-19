package iehr.security.api;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.ExecutionException;

/**
 * Created by smenesid on 13/12/2020.
 */
public interface CryptoManagement {
    /**
     *
     * Responsible to get private key
     *
     */
    public PrivateKey getPrivateKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException;

    /**
     *
     * Responsible to get public key
     *
     */
    public RSAPublicKey getPublicKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException;

    /**
     *
     * Responsible for signing
     *
     */
    public String signPayload(String payload, PrivateKey privateKey) throws InvalidKeyException, SignatureException;

    /**
     *
     * Responsible for verify signature
     *
     */
    public boolean verifyPayload(RSAPublicKey publicKey, byte[] payload, byte[] sign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;


    byte[] getUserCertificate(String userAlias) throws IOException, ExecutionException, InterruptedException;

    Boolean validateUserCertificate(byte[] certificateData) throws IOException, ExecutionException, InterruptedException;
}
