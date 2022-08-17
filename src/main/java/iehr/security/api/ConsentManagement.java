package iehr.security.api;

/**
 * Created by smenesid on 13/12/2020.
 */
public interface ConsentManagement {

    /**
     *
     * Responsible for consent generation of the RRC to the S-EHR App
     *
     */
    public String generateConsent();
}
