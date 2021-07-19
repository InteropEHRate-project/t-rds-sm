package iehr.security;

import iehr.security.api.CryptoManagement;
import org.junit.Test;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class ConsentManagementTest {

    public static final String CA_URL = "http://212.101.173.84:8071";

    @Test
    public void testCA() throws InterruptedException, ExecutionException, IOException {
        CryptoManagement crypto = CryptoManagementFactory.create(CA_URL);
        byte[] certificate = crypto.getUserCertificate("GRxavi");
        Boolean isValid = crypto.validateUserCertificate(certificate);
        assertThat(isValid, is(true));
    }

}
