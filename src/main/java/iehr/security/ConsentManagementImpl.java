package iehr.security;

import ca.uhn.fhir.context.FhirContext;
import iehr.security.api.ConsentManagement;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.hl7.fhir.r4.model.*;

/**
 * Created by smenesid on 13/12/2020.
 */
public class ConsentManagementImpl implements ConsentManagement {
    public String generateConsent() {

        Consent consent = new Consent();
        consent.setStatus(Consent.ConsentState.ACTIVE);
        consent.setDateTime(new Date());

        Reference ref = new Reference();
        ref.setReference("Reference Research Center");

        List<Reference> perf = new ArrayList<>();
        perf.add(ref);
        consent.setPerformer(perf);
        consent.setOrganization(perf);

        Narrative narrative = new Narrative();
        narrative.setStatusAsString("generated");
        narrative.setDivAsString("I have read and understood InteropEHRate's <a href=\"\">Privacy Policy</a>.\\n\\n"
                + "I hereby give permission to share health data to reference research center to process (view, store, edit etc.) "
                + "the personal data stored in my Personal Health Record on this application for the purpose of research. "
                + "I understand that my consent will remain valid for these purposes unless I affirmatively withdraw it. "
                + "I have the right to withdraw this consent at any time.");
        consent.setText(narrative);

        String encoded = FhirContext.forR4().newJsonParser().encodeResourceToString(consent);

        return encoded;
    }
}
