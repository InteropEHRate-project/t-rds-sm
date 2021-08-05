package iehr.security;

import iehr.security.api.ConsentManagement;
import iehr.security.api.CryptoManagement;
import org.junit.Ignore;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.concurrent.ExecutionException;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class CryptoManagementTest {

    public static final String CA_URL = "http://212.101.173.84:8071";

    @Test
    public void testCA() throws InterruptedException, ExecutionException, IOException, CertificateException {
        CryptoManagement crypto = CryptoManagementFactory.create(CA_URL);
        byte[] certificateData = crypto.getUserCertificate("GRxavi");
        Boolean isValid = crypto.validateUserCertificate(certificateData);
        assertThat(isValid, is(true));
        X509Certificate certificate = crypto.toX509Certificate(certificateData);
        System.out.println(certificate.getIssuerDN().getName());
    }

    @Test
    public void testConsent() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, SignatureException, InvalidKeyException {
        ConsentManagement consentManagement = ConsentManagementFactory.create();

        String consent = consentManagement.generateConsent();

        CryptoManagement cryptoManagement = CryptoManagementFactory.create(CA_URL);

        PrivateKey privateKey = cryptoManagement.getPrivateKey();
        RSAPublicKey rsaPublicKey = cryptoManagement.getPublicKey();

        String payload = consent;
        String signed = cryptoManagement.signPayload(payload,privateKey);
        Boolean verify = cryptoManagement.verifyPayload(rsaPublicKey,payload.getBytes(), signed.getBytes());

        System.out.println("Sign " + signed);
        System.out.println("Verify " + verify);
    }

    @Test
    public  void testDiffieHellman() throws Exception {
        //Alice / RRC
        CryptoManagement crypto = CryptoManagementFactory.create(CA_URL);
        KeyPair aliceKpair = crypto.aliceInitKeyPair();
        KeyAgreement aliceKpairKA = crypto.aliceKeyAgreement(aliceKpair);
        byte[] alicePubKeyEnc = crypto.alicePubKeyEnc(aliceKpair);
        PublicKey alicePubKey = aliceKpair.getPublic();

        //Bob / Mobile app
        KeyPair bobkeypair = crypto.bobInitKeyPair(alicePubKeyEnc);
        byte[] bobPubKeyEnc = crypto.bobPubKeyEnc(bobkeypair);
        String bobPubKeyEncb = Base64.getEncoder().encodeToString(bobPubKeyEnc).replaceAll("\r", "").replaceAll("\n", "");

        //Bob
        KeyAgreement bobKeyAgreement = crypto.bobKeyAgreement(bobkeypair);
        KeyAgreement symkeyagreement = crypto.bobKeyAgreementFin(alicePubKey, bobKeyAgreement);
        byte[] bobSharedSecret = symkeyagreement.generateSecret();
        SecretKeySpec symkeyspec = crypto.generateSymmtericKey(bobSharedSecret, 32);
        String symkeys = Base64.getEncoder().encodeToString(symkeyspec.getEncoded()).replaceAll("\r", "").replaceAll("\n", "");

        //Alice
        KeyAgreement aliceSymkeyagreement = crypto.aliceKeyAgreementFin(bobPubKeyEnc,aliceKpairKA);
        byte[] aliceSharedSecret = aliceSymkeyagreement.generateSecret();
        SecretKeySpec aliceSymkeyspec = crypto.generateSymmtericKey(aliceSharedSecret,32);
        String symkeystr = Base64.getEncoder().encodeToString(aliceSymkeyspec.getEncoded());

        assertThat(symkeys, is(symkeystr));
    }


    @Test
    public void testEncryptedCommunication() throws Exception {
        CryptoManagement crypto = CryptoManagementFactory.create(CA_URL);

        String symmetric = "UiYmJk/iWopGS2n0YIhZsgp1auRVyahR7sgFOtEC5r4\\u003d"; //encryptedCommunication.generateSymmtericKey();
        String encrypted2 = crypto.encrypt("sofianna", symmetric);
        String encrypted = "GgM6KU/LASiCZS2kBdCIEyh/jVEmJCuj9XxlANubpUUq8cygiaIDLU+yf+gDKFQPv4v+7jVEAwh9\n" +
                "k3DnZwQeOEvHljqo++Voi5GdqGOOJ/g2F+riDiPmGE/CVW7gie2jRytaPk/5y31XCG9q9JqsEaNr\n" +
                "C41d0pOBkMppr4RpyFx4/FSaDQgXXLrYuL/EmIIHzdMMLHy3UmUqPLITpQ8X0rm4/Z8MvlpM296k\n" +
                "gZ+YwU3zaSvKMHQM58zf/RenQMt53jNS4U0jvplbcPjV+W8kVbEv4iELKQ5ueldFim+l++cWYT/C\n" +
                "hbccZKH2cTJzjjmZrO3j5whGqGOrz8wDypXYVX/fau4ulIoETMgYRd5GbvgU8i7XgN2HN6QDXStr\n" +
                "no1x+oEFMOAKjhLDGaQnqi+gkSyUGyP1Fu3lpkFZ5q3rpKIYmdL4qh/qqeqRceA1dtikTCe39S6E\n" +
                "g4Vcm06sjmy7VLQcyO7mJVATraCmtDMG6EIdMm97jQ4CsJX06wJljsaFSfgdayzNrcMsHoEaBh8d\n" +
                "kdHHGQfyhs5ZciyyJtmceDXvtDgAJSv4iLuBqrSnRqxzGbuhvMagSsxRJKam1bujyNLRbLAjjeKK\n" +
                "NPvAfkfcRtPbDl7DhsrCoYkdY5S3IUsjyowiQCN4nVzDx8T+uDLFr10L70z9+vPtWjI4gur45Dkf\n" +
                "490+vaXdIyXVYIdw/PEY8190LIWkwV7gBFTjPz7ujmdA2/1h+vqGiJPZntOm3xHH6h5d1WyvmopR\n" +
                "EkfhkPqbHK74dRrzFfKHjqzEIuFRJNP08LDjeNhXKt6tjvOnqaZO9CcfzJIesBikpNi4GA1S3LDB\n" +
                "qzrmikjGGv65yJd9azV829keCz8CAIxzoE6XvAUQL0M0FXVVMQk+GQ/iMKuiZ1rSLTqjOoHr2mm1\n" +
                "npRmyQNSsAjDz3/3S/0c49bai6Xv+hAMZseyEbPfLeQ2nd/Ku0dFg+QrCJFQ7wZdICjtfGdA7OIQ\n" +
                "AomVwndI4wWemXPWVKt2mEiTrkuRo6Q2+yjOd0NAZdFFE2+0MgVmqI0b2RGBFdI2fezQoBVgCXGc\n" +
                "MH81QsKiHkY2VE+kzJ31uy6O5r8/XQykV4F2/sXpdMnkJJnHvP5h86d+DCir53d2eH/a37loSmOB\n" +
                "XWh6q6UYKxYSatUY/I51eMLJv36kBh6Fg/XYHwPxHv1BX0kdpPnr0HvWriotXCUsVOFVzjpsDKZb\n" +
                "8rUwoppmsIcVCGC4Fc9e1WvzOP3LxpfKrWnoQ8J28yrv+hAMZseyEbPfLeQ2nd/KIkiyb8470ypD\n" +
                "x9EJ3BOavU4CyclZKjaMrrMxIDUddc+VECG8W7T1bsAXq0p9D4gpKkWZ7AX4hhZ4sYkxYbVgEdPN\n" +
                "aiILUjbG5Aqcqa/QHPQO+mCA91gWeFpt5D/OGVU9BHYgKU+kETQ6d/b8MUOTZGtFBcdXhL2Z8/Ki\n" +
                "WfVq/EsU5uXIOtWuzOa5Bxxt3fOX6nURjhwLVJMsPbSsYwNmx3ltsS31/RMv6FMkll/qZdUVX2p3\n" +
                "lbbYIcwIuTkt5FvKXKwKw+bnnAhqDHL71XmwI29J3oAx6r8RuC3vB+Fj5WvFt+uI8AjnyVfljr3m\n" +
                "/8GAJ/jK9SHI/4jy29/iiaoW5huMNiiAUpUtW2WvlXA2H+lvpeNa6anpU8lXK81ZXKsLUklzie1J\n" +
                "QNbSjRCYjP8W0/Jh1sTGj01vTsq92yE6AI8KuWa24PHQFQXy+H+OomSatz0mvHGGX0se+mUkqH+k\n" +
                "4x98b1mHhcL5HNZ4cpsx1QhS3e/jMnXMxD6yRAzvkU6P+GyriQQKM+PWsIgPMUZBoMsA0PBW+byR\n" +
                "FSVTIivICfCkjl7U7hG2IyAmK2wvZKWVM2OLKrXoLXBjA/DU0al7qZiJ/SNx/ixaYIcZxhlUrCyi\n" +
                "BF+HwbSbuSOBdTJ+PGFbc66VXLc/Nm4smVX2tkLtaYh3SM/CpLTYIntY1b+HdU0H2y2M+rVUQ2zG\n" +
                "QMYCUX/IAUB7K7DJFbeesnosyFlW03gPomgpEq3A7/6rTB2PZtRQSdxprIWiu3zg2rKNfsG9hv2E\n" +
                "WBspkKJ2iEsu8Qc3bGsoW728aE6E26FhhzuLKWBj4A0kBv1uqVaJdhf+oZFfrIs3oGX2YNY5+61Z\n" +
                "zLAg9Wk112f+yWDPaWOJvE1vjiSr1b5SKzj5YTdxRL6aFkBtNJ+FM/HstmIni4WkCUXuqMZVKW01\n" +
                "TgNl1k2iSFwuhKvGS7Wpyl9RbxRTNlVPbUizbo3iQOjXwj9ASm54u0XDCLhVS9aYFsQzF4CcFSXX\n" +
                "BuzE3tSI4wKvjsU4bqRVnaSEJQshJTEghoU7q903WS/R/YbvgHKB9eH16IFvXbAn37uE3XKwSc4R\n" +
                "x1BCEhrAKpHIqE1k0D1Zopaqzq0EC72RNmHziHAno10z/7UfSXb//PBl36bqmM2GndQjlJgw+tzf\n" +
                "aV6k00zh0PaXHUW/oHeiATHSFj+9rXhNxAjr53IuK2x9F1bwC7wpnp/ENeW1EDKIIi4E+uwrC0zH\n" +
                "LxOaE+/H3RppK+2vvDVrPswvFLKfWIYZvP+4yhSHzqcbU1ZoyZ9nFVrqy1ps1HRWuTqkF/u66n3d\n" +
                "PPSHHuF/KsdbwpnBEZ4lm0n9z7ZNqQbnpmX/6wcwGDTcd5HysPAurMmGmJK/TXMZzzsTzpi6sGH8\n" +
                "lOCVqHXv+yMGKy5D4YtNWd0BWMYn83VtgGw2Lw3im1o/HvZIwXh8oV5h2XcbFFS3F28vF+8N7wFa\n" +
                "kRbD6qoAVDQ/hm7qFztQEEJ96RIZrH9wuXGG3TZTRGboGufkev/aXcpUXZldWtZXkOkJLGCdAKkZ\n" +
                "Mi3V6c1zp+rMJoi/cuqjrrMQ2EYKTMYr5DmBAbz/v24DxtEc+pCjS0Gf5DU8qI7QLbrdo7mhxbYG\n" +
                "U9BuvY4YqWr9+S1wiDYSeWn8r4B+mr/ZRfO7L+ZOXr7q/fNOekJgZlXqcXX4W8bJC3wOnaBcOatF\n" +
                "DP/vCEwKn3FBM4OrtgZw7YPGOtG2BpqdqMOrleb/xIWjTeATxm6Desps0RDjByMLqMoKrZXRCDuE\n" +
                "vAq2MG86Y/421uId6ThSXcTycfu7dNuvDwsw+zkHDTlSRO9Z82YGX7GIWMnhADgXiCEh+kHmc6vj\n" +
                "0PZRiU2sAKq1DbXEOHiE6pZ03Kk4FWxgsLyjc6NewpZAuIh6m+pwdcfBRmmNDDlIz8V5vuAVrSV3\n" +
                "mn9Kf23F9B+4M6cqAwNBNbE3Soxjzk7nIOzIVmq5OAdH5QSWhd+Y7O6R1q+AS0IUqDXEDHDh7Fn7\n" +
                "9lH7h4fLZs6cm3w1wLwJQnbK4oLSeGRIkMhHw+gorQaovCxHcXromMYxe+OmzlCEWsTwywCanxWa\n" +
                "qyRVXR9Xhjb6tGasvfNIJUQbEJY2gloJeMGQ9Z2cGFIQ75Dpex8HwhCZetRjg9y5oYPzYJJ43kkL\n" +
                "lVacOnM19LBLg81x9fE9/MxNKm+ly9YhAUALUU2xL2AQYxBNkceCT2UyBJRT/B2cZj9W5pigf7fq\n" +
                "HRcGxltkcMYNa5U4YmXgl5CtWjQYERUL4kn907uFObdtGv/vCEwKn3FBM4OrtgZw7YPGOtG2Bpqd\n" +
                "qMOrleb/xIWjTeATxm6Desps0RDjByMLqMoKrZXRCDuEvAq2MG86Y/421uId6ThSXcTycfu7dNuv\n" +
                "s+XoRHydIEml1P5suOLkcYEL0kSCYPqFaVlzEBySNIHb3W7M7+WN6fit/HV8UiD0qCAez0YDVsSz\n" +
                "wt5oURZNSvfUzjVmkx6fBUBXAWAch5406Nv76UnjSDKEuFYaOBA5W1f1welscaEP7QcLhAN5XiIq\n" +
                "61iN5KPtmVUlZUX4z4iVN/hOPG9WzG9nMlSYueouG+HBXnCLZAlYoQQKhSCysCTgmXxAZqeWL1TX\n" +
                "tqw/j/O5s8vY7TkiPMtPcZ/xOKH0jsaePbpqxCNJ5XhuVpscbrJfalGiQz4Pej/Bcp5CJMAqjqej\n" +
                "yPT85hbBG9ICyY0TF0x7jPaRSN3mQq79MH83YMh+l1f8+8/1d2J0nsBbWmLAI25KMAqBI8gli9BJ\n" +
                "+7SJJgRbZ9zbzvaz2NVLMQ5+boWzTbHoadmcWQCqPkvrKS7mN+24tqc14Nnq9jXqODhUVKldnxZD\n" +
                "bVSiNoGfaGfEqtHR7cECrB3BBHFT6CUf/Ju32vHwF7FuWbmtNNB3RpH5RTvBNez9jsrqP/BQ4kuF\n" +
                "1IeNR3fiNrp2HTooJz1hNmKLMXOI4dtXtJ7V+X1XfPn21sbtbcATptAOSRgyhFBweflymcQG6DLr\n" +
                "savJnJPUbELTL1RXCy5KOf77q2o8vqVxLvDOqnvu2HYJhQphCp/8Qx+8yXMXeJDuEIOcTouJaq+O\n" +
                "oiguT+hwP4ol6PYIr0jv8iKptczFIgDqSyfABPzVWPWLIu1jIG5O3ccLkSF1W9EYAb4oYO6wusj/\n" +
                "GnW2ATSoix0v4HF8mRTR4FB9oKv/rDAxdQa/8AmRbgKdq116Yn3vZCoSWedR9rauSNgF0ttilgJV\n" +
                "70TFu3BrIysasKkdgCMUJkBO2rutl6SBtiJpS7zrrvvupqSWlpy6tHkiG2s1bX0o+69oj40PvkZV\n" +
                "dq1p+ASnwqQC+YfBvyiDSy++LxqvDn+ZMaIxSMxDti6Bkge9Pi/AM0wm++qFjQj9O0BAMQLvZ4gn\n" +
                "fKq6psYgiad+nnFCAiSCnYiH6yNlfzdjdiVZT6+Lkrjd9h89lNj+nEYFHjZlTOn5ejxhPyvcpudG\n" +
                "mRLXXp/TGazCHuCHOK+8LR4ugkEVMFcnHIxWOBdt24jeKmF0V0yiHqWzmMgzZE+1jxHJfETqHwAf\n" +
                "8ftM9vB2saSQPjOM2h1qs3+n+J/Yj+VVCdY7JQKxRQJlSwz3Wv4O/1Y5JuBufKWKlooCKgOyOR2E\n" +
                "XWiK9mwxllVJzDY5aNu5F7XvfCJWA8T/IDFBylVZJBe2T5r496YOG5OzOR6f+luJVBfRedEPGLk8\n" +
                "fT6HQo5fDcsA0PBW+byRFSVTIivICfCExlXOIH243odp/SWn5gbRgUB8oXTeQZtSfRb4SMjXYxuB\n" +
                "TqfVbRdJyISz5FtLPHHJFOMEZoUpK2gVqJ/9CPfBp7h9c/EA9gKWVjbW3Mk4vl23EDiT9XLDfVlm\n" +
                "CRajplXXKw3ta1/IzuIEBDKcCnaUkgR6DcNuaGn//otUYeOhTWI2l5bSUQVs9Ams8HPK38LBLqsU\n" +
                "wRoa/R21PBlgzAgjRgpMxivkOYEBvP+/bgPG0Rz6kKNLQZ/kNTyojtAtut2ZywF3mxgpV3uKy2yh\n" +
                "5nZ0ttgKfgZKVL4o7G3CcNZMuoVq4/hepbLdvxotX3oYIPQzVjoXDgIzCXhPKXl9X88Ib1UZxMN7\n" +
                "C4dIWXeeJqKHgd/sFSVxTZbTpDnCqGHzW4FAmsbigAiWHtD87Ygs2d2vGdq9toSvvWBmzAchW8B9\n" +
                "qTHTYG+3guXleDKJmvUDocDaPZGtfd1LJ+JjgD1CklHGwTnZjRM8VYWp8tdR2QMnL+DNUsRzFf8E\n" +
                "OK3bYrr9TEHWslvkifdhPnXxVCvWmkkzql8BRKt1yX9N47XB9P17pGpXgPIAkLQaas2w+pNdaaoq\n" +
                "OmXpt2aa/YsFS6MnC571m40nPl6lOkvLFcRd1AgFZcT5qVhxYJdt9l3d08hqx4609drZM2LiPLJo\n" +
                "9P2KsIMEeub9nAhvW6zMoeXrkvMiCtHGa3+reJFXlhhYdIVbnHlbAq7/XrXiv7RAi7+JxYhZhR1/\n" +
                "No5bFoljehRcuk1PbHnDc29mzDkNJgDY3kyoquaqbElSBMHnfA1aP5kZZj+X1l82hc79CJuVJbT/\n" +
                "gGgqgY3GvxlSP/tXIpB15Im9yKnDHcRTLxtO4PFycdTIFmfPWKapgyfqqlotQy7sMTGv3ep1EY4c\n" +
                "C1STLD20rGMDZsdHohclAzIbvrZ0sjlvjhwKbYzwgwI2h+6RsoTeHnKb98Pzb8XyA6YBFPh90DQB\n" +
                "AgXECoAExqBJXhAcqVu1XDqCt8HSSGVeW3yzS1udjxYCaKXHpTvS2IUW5lI2+FGavG204+aFugV7\n" +
                "sEDMWwUoUz/9SJD9RXRTwzSHporMujnMX45fR0xfVgtrvsZ3oG6XgeciTR1elOlL+0B+HA2v/+OW\n" +
                "M7T4rxnLxodHH9e4Z5hth/1+BigIJ180pG/TOweY+8zd4GCpWztUkz248BJj/RgGm42WIJI9qmZK\n" +
                "7JJonXvPIi/BcEFYROU6whEEKbRQAat0w8gwNB8sARNXCmN8+ulfHu8tAJXxF0kXfP/fi1YBCg7N\n" +
                "aCIDQT058gG0SZ/Cgkbco0BfxYp5ubIj/Qz+ngQA4jPD4zFgOFchQc/dVAGaPzNTCAtrIgiF9dyj\n" +
                "0UqcIvYvEaxCAGD2s7byiRk/kh+BNEDfKzEbqa5Izq+bmDtA/zJlcdGWu4BSvXEi73iw9VyWePkm\n" +
                "wmQs7+TuTAmpoS95psDhbH4xBfR0R50cqoqUag8QZ45zjZyqdsHa3O5Mi3zqLMFyWq+2hpq2ZZoT\n" +
                "9lAnVtkNiP44IGmBODRlXqIQny9gfBTB1EM+NMKFd0TBAJ3RLCNPNEnKu3tDiA7tcoOYNLkNkX77\n" +
                "Fu1mVIl5+4aWoI6iKC5P6HA/iiXo9givSO/yIqm1zMUiAOpLJ8AE/NVY9Ysi7WMgbk7dxwuRIXVb\n" +
                "0ZFkWF/XHCjVn7BgRpWpiyxdg1AarCvr7hGjJd7/uXaR+oEFMOAKjhLDGaQnqi+gkdR8A7QNxp3h\n" +
                "pra1c++Jyt2c3siVKjw8KK/jIpj8rjPCxZa+KfUszdqtW8ldeppplSSQYdvuNc+yIR+N9SgYd0mi\n" +
                "ay2+sE3nN4mAYtOqCgOXMOHkPzcfdBdqhHdHywOzo6CvGuFM+u/RQST0KVuOpKbhkWj4IML4kujR\n" +
                "L9FaDWu5vNAey4R85FPKwOraI6WtpfYpcg23nrzSJLuimnwKf696I/AUFAsexJ9+54L77W0FiTLM\n" +
                "cO90DW/+4NelpnpcimKIvTuLzc2Z5On3tIv7fPzDvDEHSsTPAqDzOJzL9+f3RSNJZAP7axZgla3+\n" +
                "O2m5gQQ6VkkwlpT+dFkQDVdnf/EX6G6k9y5DECE2XQmQs8f2xN7UiOMCr47FOG6kVZ2khCCCX5Uk\n" +
                "Mm30VVGLg/5Zh7lJBv3lfQ2/86v5Wt21YjJmYUO/U1SIYUWAqocTkDiFtwHomYPg70osD45hPXea\n" +
                "DJVJOM0HVm2oFisKoYkJua4m+WFUWMFgXCP+dMt9IqfyoeFvvAFQdw+dZjpnqL34n17leYn3LrOO\n" +
                "dpIrCQVQTV8C+zsl6Vb5oEv9BpbamRMFYhHSEkk3mRGYHR0htuDhb0vtUOjxlN1+H12L8h1Ir/FC\n" +
                "t9Auv2JdeIPoKpj8eYr+zDjDg1O/u/Z8gSY7GnSNhmVtVgeFTn674B7L+OtJsAvT4dcJF9tki7JK\n" +
                "Tz0CldnCintaMbiCaPnUwhv0k4YYnb7/jZ1avGqlvCKJ1yW0HUcsujl+djUcgQFVrzlVxRBVX+AM\n" +
                "4NMGI6I/kbuXy4B/1j1re/FFfxKz2arwa+y7PJqxvdK1/m6nuTzSj8eTIQrPVME52Y0TPFWFqfLX\n" +
                "UdkDJy/gzVLEcxX/BDit22K6/UxB4aqx49jj5KgxtisoPECFr8Cl8X6mOpX7YDdlfFO7Ecq2RxVl\n" +
                "qUq6n/YhXmbLD+6JRH4vg1ImBtKNXa3lfTXA4ITdcrBJzhHHUEISGsAqkciMkj5QBuBGqzv2Gapu\n" +
                "gsA/Ko6no8j0/OYWwRvSAsmNExdMe4z2kUjd5kKu/TB/N2DIfpdX/PvP9XdidJ7AW1piwCNuSjAK\n" +
                "gSPIJYvQSfu0iSYEW2fc2872s9jVSzEOfm6Fs02x6GnZnFkAqj5L6ykuE6i9FIqqPedgE9i2bAgp\n" +
                "rbOm3NBHZnjaD/5TGWY55tMs6Y+rq2Kz0kZ3Dk0o2j4e3Bf+pFV6PwaHFBOWk5CG3yprgGarGXyF\n" +
                "GZ7aMBOl7Uzbjgz2s20uZqEwsjmqfPLeF7cSdzIob4SI1z6EV1LnGT5f2dzuy018Nv/46cXfcJkE\n" +
                "Y2PnSGGLyHiVqmQ/kE/dZKklkrmrLgR2jgB+ZTqUI1bZDYj+OCBpgTg0ZV6iEJ8vYHwUwdRDPjTC\n" +
                "hXdEwQCdblSKPWIY/Ce9yXNQmyCB+wacEWJrr+4iGIyTcnBgnKEjUwdtFh92kfkZWh5Vf2/pDyK+\n" +
                "XMrvxHROmWk1H/kY9iGd4miv2WeaTcAY8rltlF9z89K35TpZ4Y6f9J0HBerC9a7t1eezF8C6VFw2\n" +
                "kyGc5eCdbMr6Q+fudONl7csiIxZbOkAZguv+HN7XLGpBEv6sHkj6N9hJYhF1QVIEv+mpdX634nOV\n" +
                "suBo7PJNJup7fxPZgcQdRD5rooZa+/zg+xraPXPn0lTaVn3LDIuTBrwnYjtfJ5JrznnmoMiHlJY1\n" +
                "vU10m23Jg/I8DYKjZ5FwQxEfPtFqmmXDRk+V0aGT98X2shfu7z/uyFRUmwlV3r21l/QdGYuArn7N\n" +
                "qngNL7JNcksgq7VmjpDMOP6SVhoIHzWR7l789/E0etSfEMvaBiddN/B/mEy3bS3NdQH8pGCl+kLy\n" +
                "80ywgtqxbKDrUFCfgFrbMKi71bK7tDrXu1+D/wZtdtgkr5GllGd10v3tHrPON1/kc0nQ57W75Ji8\n" +
                "kfj8bnNkqmFIsbFo7jfci+Fm6ZPgRNXmqG+mVLFFfVhR+pwfiRAA4a/jGDHrxdtu6onvC75OcuPe\n" +
                "rcx/Q6JJyKEVox45aLsp9wje3pqzaEvdglUaT1v3qmAsL3TxMt9N5+gUKR/waLAHFsc5d8xUTyhm\n" +
                "bMu3AOj/76Bh5W7E+86uQZ3gkBpWsiNFlqtxZqaTnnFpbPhBx+gR9noKpSmrlekf/TCBKGUE979N\n" +
                "5u7R1KW6ef/rBvrpF8FutaGOG/3rztuKpCueK7kRCPb6pLmiy115TVtFAZHjCXgKBuXUmq05iUte\n" +
                "+RYZdzlXbPtpR/CkniOVf3luH6KXa8pqJetOvrDqpmajg6PxZkP4SN6RVNDiYXgxZ3seOx61Pou9\n" +
                "7rlTTXb0pHlwP7V3oaGjAVy1ff1byBGDqGt7VpL/Y4lh9hDpJI3kP5NiTZ6r5FSX+7oyjHyPvzrZ\n" +
                "zBCi7DuG87T85wz/fMUZfM/TdAZqilGgqabh+KrPTES+vJ83zu1p0S2DDWLu44NnIBIHL2WMh++f\n" +
                "lDmILzuFQGp6xHtdZt5CWj9DEW2YnzCDdO7DmbElx1/HLzTc5PHkt/s7JelW+aBL/QaW2pkTBWIR\n" +
                "0hJJN5kRmB0dIbbg4W9Lx6acnKKPXdJiSZgggwvJBLfQLr9iXXiD6CqY/HmK/sykOv7OFuRYey6i\n" +
                "K5Jdza6ITF3QWYwx3Px2v+LRHdHdeha1iiKFIQJk/iaw8hL3GWrLANDwVvm8kRUlUyIryAnwKMDA\n" +
                "s65KoYaec8HcVzmsM81TdOxsPIzkduZzvOroYQ8Kh8Q14RC8PkJpZtKfj7XrhQMriC6VBP/ebme8\n" +
                "ta5EKcOU1JcJa12ZqTvRmGJvvkb7Ajg+191DqnscKIJcT/qxL9PJPe4w7HuJAMzmzmqBXX75TdyW\n" +
                "q38QyiV9boYU/oQD2SkORtz+GssrCABJxVXt0ntq7NoeMl+WUlQkbcZ5qLPHw/7/zH1NyFRl1Sft\n" +
                "Ps9j7dDhvLM5wJ/rem3/3VjcFttw7JcaHB4eYIhft8H8wEEW5Thu5xViSnqgLXjQjjRGSc0HAbC4\n" +
                "cKZDsmiaES15jxNxQxFtrFQDHLhAKqJnlhfl7nPQr1WN4mFoK7P3IXoaAzopT8sBKIJlLaQF0IgT\n" +
                "bo3iQOjXwj9ASm54u0XDCKz+rYH1rd3RF3Dvr0UCCbssWm3/FnZcQLROnrcyzW+PUpx+0ujxx5TN\n" +
                "l+yC96b/RtBLxWXkCM4S7YjSiHtVTzC2HzAlIIgM6pL2HQx/bVxAjBb8se2EyydbcuRyBqnKBcrD\n" +
                "9fkE/yIpr9fJ/ZH5MRxJkptLxZGauDvFWpaSNG3/mII88kvy79HQfsGYusdPcsQ1LA3jkaQSe5hD\n" +
                "V1vjorJcQMbvFdvj/6TnzU5TBaGZdqgQU+gJGnO77Sn+FuUjFRT+UHlHrZbt5npITy2f8hSDYX8M\n" +
                "vNE1NrM55IdKPfi/iyswH0Q4B1yhs8+lfjb0a1PPqbThEyIBDRNRKLjFbml6yEPjjDa8ExzChmI3\n" +
                "mawMi/X2Mz7QiTlyasHpsuK86Dvimybk775hkjHY149t5BG6+78c67sw+I752ZWs7PZVqCGcMN7a\n" +
                "lOsq5mfYoSWkM3lsbyx+ybir+mZjTsDnh0NN9JHT157zxYolusacHPBBX3d4sA8y+5/s5s4vBJY+\n" +
                "8HC9B1fznW/mA37XkxSjxmOk4K7PEswq5sgIWPOUbh+HFSOY5TVVFhlcZ+LTF6BxKmlEASlKtnfH\n" +
                "o3/IR0hj3RyKqFenE9eRrDkBKIZm1FCMkuvQ/p68zgsiMXRFNJbZmpP1TS5RLNDyhL4gQJKddrd5\n" +
                "SFGPAejQhZ30NoEFE+7NIh1g8PLUULvocXtxAOF3oU2A874CTDBQ04v2u6tbYUxQot2Bys7FlwH8\n" +
                "sLpQ/uWmcRfPedCMwTIzPHzxajNErjIvua0clYmiS6lugqr9FLPO+n/uiBJkSXvmMBUOiH4unKnf\n" +
                "w4QTDSkHZz4y+QPcBFjUQ7UBH3TfIvo2pE1TJrsk+lYlyamCJvZ9UF67oWwberZ+oTbowrjSmyLm\n" +
                "ckJLtCmzO52UqAp7bqyZfsyv5qI78JxacA9eIR/uYMEaoeZkafQzczJTq/KHhTFsNxgoIaCS9srK\n" +
                "HsFmjKPoZakGWxnE+alYcWCXbfZd3dPIaseOtPXa2TNi4jyyaPT9irCDBHrm/ZwIb1uszKHl65Lz\n" +
                "IgrRxmt/q3iRV5YYWHSFW5x5WwKu/1614r+0QIu/icWIWYUdfzaOWxaJY3oUXLpNT2x5w3NvZsw5\n" +
                "DSYA2N5MqKrmqmxJUgTB53wNWj+ZGWY/l9ZfNoXO/QiblSW0/4BoKoEMxeDUQYcze6bi+2AgYiqD\n" +
                "HB8vbMlX5xT449R1oOoduBujhyPmYZodq4Nb14kfZMug5Q+ZCiLLh1o6GoS89v4oIj0phTFWiUPX\n" +
                "2f93tRKYRDSfhTPx7LZiJ4uFpAlF7qi4m6hanWeNcewq5OOKDgIhMR+/E2TSj2ZUC+IWiJLzlYvs\n" +
                "A5+x+3utY+A54VDvsYy9WOXHgILvRtwoLf98s+QbV4+74Gc2wpmgNpNPSVENLUK2RxfJ+zyCLF0U\n" +
                "vT01Du9fzWIybtlY/YHAHBCqcpzBISoxsuhKYWVZXcl4OODuiv2TECmT/Iu4mU7qErRhWKUwA2El\n" +
                "Omt0/dPmIaT5tedOIXoDohnWjQl2Rs7vGYVOXhebKRLs14msneVfsFqt4Zvlqo9/YWLKf7H4Gwva\n" +
                "t7lRpOZEb8izXLLIT6SUJnfEdqKgGbJAZxF5kl5WGy3h2xnZSimL8eu8LG9ClrTnBv56HDuErmQQ\n" +
                "nWKuIoMd4Zjl5241go37Za0gLFdE/dGwkxi2WSL+VRFpojY30rnhp4LffE8wwlD4vrDoVRAa9O5K\n" +
                "zVpzGoMCK54ZHyqDti/5ZXbOswzemUblPKh/6nMlr1LqEVSAuASKyNO/eMQh/YlxTpNE+tLzXBe8\n" +
                "O1H8v7xtabhAmN9HcDLS3BeBRmMF/9VanKZSwYus5ndLjpN8dBV7qdTH5tmQt5vsHEGAyJ4wmpx1\n" +
                "EKLvqZRA7KEyUtujp991w4oGLmYbmPHuRgT6xNRq/kMoHnFd0mm4+fZwZy0yzOXMCKvXvs1qxNwe\n" +
                "hQmEfdOTeBJXEI6quc7NCQK6luZESwVppwijGKV/QhzYm3u7jmS8UsxpcwoAH1OJTK0tcldsB2uz\n" +
                "a1MR3Q57KwudeAVjb/lM5EO7EY7RsteKHzdiTNK7IDsjtFN6bOlZsEvY3gaYrMhxIWYC3w1xjqqV\n" +
                "X3g6XLgUZ8yM6GXwMcfqmIm+b38nuApv3Uf+NYewine6hTOS1rdB5/AQp3qAgRnzR7xjWqYdHuQY\n" +
                "HiIOCA76sHiOgk018154phI6zHWKQHzCkW92pzj6rEkmHDdLLfVcpbskwbtwG174ifrUHEaLgAdp\n" +
                "5VDuecqls5ytFz5pgNpBRhAaehTtL504HI7Vkfk7LFuxHQRjY+dIYYvIeJWqZD+QT92G2toPWc8l\n" +
                "00IGqYjf5CwvT5u8HyeFY8Vp/d/uNyvN/jzEub5L/3yIwA1P19QvGC+GpEP/vIZ5Mv3LgnODdsfe\n" +
                "kIu2I2es3kAcZ/HGkncFidkCCcHcnEUyGJe8w0MeC1l0GCReHqte8510FXWVe8Y45LW82lZxfl/f\n" +
                "1fQ1aFjOGuJcG6dRsD9WIm6Deonr7Wk2B4rKzJxS1DDpwyN/bYZ9LS9u8X7CLJLElP6KDERHJQnY\n" +
                "hLpI1GFC+WQslNc+f4teRZ0T+OPj12JPTW3Q9xePk/VNLlEs0PKEviBAkp12t3lIUY8B6NCFnfQ2\n" +
                "gQUT7s0iHWDw8tRQu+hxe3EA4XehTYDzvgJMMFDTi/a7q1thTFCi3YHKzsWXAfywulD+5aZxF895\n" +
                "0IzBMjM8fPFqM0SuMi+5rRyViaJLqW6Cqv0Us876f+6IEmRJe+YwFQ6Ifi6cqd/DhBMNKQdnPjL5\n" +
                "A9wEWNRDtQEfdN8i+jakTVMmu3mfeEI4ksONIKiotB2rFbqaUgwsQN8AiMMceJ6eMtYZGgM6KU/L\n" +
                "ASiCZS2kBdCIE8m6AokYeXOiZ/W2a0xaUwOvNbncfmjPvmc3bhZ2TWEGxPmpWHFgl232Xd3TyGrH\n" +
                "jrT12tkzYuI8smj0/YqwgwR65v2cCG9brMyh5euS8yIK0cZrf6t4kVeWGFh0hVuceVsCrv9eteK/\n" +
                "tECLv4nFiFmFHX82jlsWiWN6FFy6TU9secNzb2bMOQ0mANjeTKiq5h9Lbt+HCuHuyy24eheGMKPQ\n" +
                "68/LA4ZgMG4BMHMHnRLY6L/01NTDSPqttPLvtXhvZ6RVTKhgCayaYZOmIh6Apr0xHl+lz6ZlT2RR\n" +
                "xOVIOv2nMdIWP72teE3ECOvnci4rbLANsbMRsL70xtHujoqGJxCDTSV9onsBAv1WARvcGiIEdrBc\n" +
                "ylmi9UshlNCxnuWbHuvwbDdMOPfmryE0nZ532JvuP9n7U7ivbPtUMqGH9Hu/PSpW4edJ/Z/22bRX\n" +
                "s4m3ecfqHl3VbK+ailESR+GQ+pscrvh1GvMV8oeOrMQi4VEkrQ9m6G8m+JWZltJ4Li54DU+kbOxq\n" +
                "iHZo/Pgq9+SroxgMWBO7VVGbLkUrExXp4el+Yw1n9DdWMTl6fwYpd5aEEFHyY11OkxDXES77LAuz\n" +
                "ztDY2UdIzWGcJhQI1Zm7bYv7mjrRgdGZaLWSAdXKZBK8DCONzJ7NeHYyQp9RUZTuMP9zE4lYzS6w\n" +
                "9CdvsSfnmkfNitf1y5lYB3aVgsbR6MPaUPhV0mCRAs4JUVY9YWMOihuCRmzPkl0I1GQAa98u7XB9\n" +
                "izm4IFcqFfjAL1WrdIR2zSA1zltDPoiVKA2bb6y7j6OHYpJ4j/T6E+yFF8MTqTEMau2EXqVu5b+s\n" +
                "CKIN5zg7O3ajh0qRhmFvgLBMLL4Ag2sYBtOQ2gCZ4xXgQOVfn6EQubPL2O05IjzLT3Gf8Tih9Hrz\n" +
                "agKJcWQukG05JUgCmz6hUTom6LiyjCRU6/pN1Di5TCe39S6Eg4Vcm06sjmy7VLQcyO7mJVATraCm\n" +
                "tDMG6EIdMm97jQ4CsJX06wJljsaFSfgdayzNrcMsHoEaBh8dkdHHGQfyhs5ZciyyJtmceDXvtDgA\n" +
                "JSv4iLuBqrSnRqxzGbuhvMagSsxRJKam1bujyNLRbLAjjeKKNPvAfkfcRtPbDl7DhsrCoYkdY5S3\n" +
                "IUsjQAinUzO1kg8aRKFvJo0Fx5E8jaoHJX4Ij/4nkHAq2wXD8fmRI/SwMJkw9VdwqeClYqR/Q1eG\n" +
                "GREwd4w5l0r1unwIH2tyHHzjA+lpfrqWCNoc+pCjS0Gf5DU8qI7QLbrd3IyIMEzgSNq05u2+hLNs\n" +
                "36DxuEkzUXgn4bvF4axyZVm2yBgzUTj1endx4iGBC1FOzTaNb6q18lz20qBKJcW6HIVJ+UIhDuFL\n" +
                "WdELgVo9vzfr65ghy9VE+YkttvDs2APXddtwjOon7xoJ/fZKSiLSV7yulYIRnc1FadS/dyZHRlyf\n" +
                "4y0NEI0fImRCbStsHGTQ4RsJH6z6byJNaLI40+XaGxyrmHBSb+3+hEoBYWZYizC3zrWrf28oSjdd\n" +
                "u/uGlAJbFAr5GQWavl1MGxkzfzi6WNPoDkwb2+sEA9vPNvGfJlzi3wWTCgjvVi8WcLKchyFqDzyP\n" +
                "GDmHlojKtIlQHuQuBseiAA1pptTLFLPYeYrRPA/vPOwnUQy4o4hj+SYJoKrqJMPFMUspF9fxkt1I\n" +
                "cwlwLdPNaiILUjbG5Aqcqa/QHPRmlMIBo1QEaGZOBj1NadQHtQIvnDAAUYdWJah2j9Tzd84id6YR\n" +
                "hBbHdC8lSVOZJDkYhHw5Pihvo9+YLd8/QIy2N5WiawyVcffv1pA+EpD5IWiGwg4O3GpMOYaGSTYm\n" +
                "HQFetQrf0hyaE40AHyEsgySVYUFBndxNR4yaT76vCi/dvOzUkbPGL9CA1LEu5Fsraw+SEXdJR3V4\n" +
                "pMebttmK6a93ODeiePf36sHENK/FIgj3MzpPCI+P/3GyWZ24ABqIH26tokcWQTWCRa32dG7x/HwL\n" +
                "dv5ryC80D3XE0xl/QVKkpWu4aRdmlD0t6VbEq0r2JupQsjsqfMcRsxCbOtTGcbB5NOjb++lJ40gy\n" +
                "hLhWGjgQOZnbCn76V0PSOdue/34NAHG4ClocrntdFI/DwvXtYGNu9uBwENKSYjL8cknsEgN8qn+Y\n" +
                "TLdtLc11AfykYKX6QvLzTLCC2rFsoOtQUJ+AWtswC+A3CC/lj3PhCOrwfMoGWVeX+Vnoksli2NRL\n" +
                "3DTyVOiLg0+wgAAO01Ca2IJCHZDk5hF7nms55AOSNVE26wTNCby9D5KMFYcUuwMoXm/Mk6fj3q3M\n" +
                "f0OiScihFaMeOWi7KfcI3t6as2hL3YJVGk9b96pgLC908TLfTefoFCkf8GiwBxbHOXfMVE8oZmzL\n" +
                "twDo/++gYeVuxPvOrkGd4JAaVrIjRZarcWamk55xaWz4QcfoEfZ6CqUpq5XpH/0wgShlMROsuJ97\n" +
                "nxaAAKLO4/L3SjZlTOn5ejxhPyvcpudGmRL1TZlpJ+sIeoA18/b1IdOnJ2ifg0sDEPRE5Rl8yj/4\n" +
                "k3DE4vIFlfhDYxFZVO5ljXXqdRGOHAtUkyw9tKxjA2bHR6IXJQMyG762dLI5b44cCm2M8IMCNofu\n" +
                "kbKE3h5ym/d6qOo+vRLNI26N6qY3vRuFbWBpX0buvdgW50rAjRJlk/NDm+h0hDR5nI/Gw8EawJMz\n" +
                "UwgLayIIhfXco9FKnCL2LxGsQgBg9rO28okZP5IfgQOPxqD4aW0AYBBCHRG9r4YC1cE4pw0g6emm\n" +
                "hY6LKJa4nb5J9aBL99k4YSWhVAjfJdE0PcryqyX/1TF9QnSGRMnxAXrulfLggAGvlC/Qxm5YMR+/\n" +
                "E2TSj2ZUC+IWiJLzlYvsA5+x+3utY+A54VDvsYy9WOXHgILvRtwoLf98s+QbK9t9XXE4l23kx0V4\n" +
                "0BQX+cqJhxJfrZk50Z+39CdSPsqXUuE4Ph1NxgS3tcTo2RsmrKeiEveTSPw//6G1xpaFXKq8H0X9\n" +
                "WZpSV1MdqhPjQcMcYsZzEChzbouDqzpPo12mZy1IBrMeba05Y7jQ784sLsPhvoRINwh2H+ljm/d8\n" +
                "6BvOJiiTpF+oQdLR4cxZEflgB+5iheA2XM6jxErAWcsHLLoLjmTHwOhywgwClLLdfqlTM9Etdl2i\n" +
                "ElzSUT6m0aQuLRhAyFQGbwF0apgppdTnNmMMrTmks7hTohmsZBfHP/ojmKqXjwKdqL65DpUtTdbp\n" +
                "HapJRC7aznpSt9dysL1Kyq+xeEDhyXcSnJpAnaFuh841YtUPNKq0tkoIPdOYmcZsJTchUE8DLsWr\n" +
                "dWrb3cIYUpo/UFNHj04oZ6rDBDqMPVH14TQJJ0mCuuZBtgCXKHATI4on+qwZHfHgpdipy2xqxz2w\n" +
                "zaH6d3p1SX8qzqSyFB3OMWbu7c7LVbN2Fyn1g0eHkvb/N/wD7TjMfzsC572soKeB5quogVoe5S2B\n" +
                "XerEETqbjZYgkj2qZkrskmide88iL8FwQVhE5TrCEQQptFABq3TDyDA0HywBE1cKY3z66V8e7y0A\n" +
                "lfEXSRd8/9+LVgEKOLjvog+cphsmkJoVQRcGn+J9euUx+ovcDnQu+bSxsbQlz0hEcQ/K4WCKM136\n" +
                "+3wGcCr7cJxfnSHf7Oo49Jw0hRz6kKNLQZ/kNTyojtAtut2juaHFtgZT0G69jhipav359GzIoYvf\n" +
                "t7Qmi8QE+ZTKfqqDzPUA3b64cf7xz+uoJ7qtwp/YtFCOoThG3bG4Wt0DVtkNiP44IGmBODRlXqIQ\n" +
                "ny9gfBTB1EM+NMKFd0TBAJ1uVIo9Yhj8J73Jc1CbIIH7bFQXbClbRB6U+A95NsvEtPwMbvg0wYKQ\n" +
                "q9DSGdEizCJ0csaXwLjgBAdgw/gvB5fstXLx+QhkSqpjCXNFvNUTirD0vILN+szi/S6NCq08haFQ\n" +
                "ot2Bys7FlwH8sLpQ/uWmcRfPedCMwTIzPHzxajNErrT69v3GM/tdK2uCpZf5V7acqd/DhBMNKQdn\n" +
                "PjL5A9wEWNRDtQEfdN8i+jakTVMmu3mfeEI4ksONIKiotB2rFbpvcZL6vBCMKWglVERucKiIGgM6\n" +
                "KU/LASiCZS2kBdCIE8m6AokYeXOiZ/W2a0xaUwMmKLY0TLHbVYFeNE9xERL9xPmpWHFgl232Xd3T\n" +
                "yGrHjrT12tkzYuI8smj0/YqwgwR65v2cCG9brMyh5euS8yIK0cZrf6t4kVeWGFh0hVuceVsCrv9e\n" +
                "teK/tECLv4nFiFmFHX82jlsWiWN6FFy6TU9secNzb2bMOQ0mANjeTKiq5h9Lbt+HCuHuyy24eheG\n" +
                "MKPQ68/LA4ZgMG4BMHMHnRLY6L/01NTDSPqttPLvtXhvZ6RVTKhgCayaYZOmIh6Apr0xHl+lz6Zl\n" +
                "T2RRxOVIOv2nMdIWP72teE3ECOvnci4rbLANsbMRsL70xtHujoqGJxCDTSV9onsBAv1WARvcGiIE\n" +
                "drBcylmi9UshlNCxnuWbHuvwbDdMOPfmryE0nZ532JvuP9n7U7ivbPtUMqGH9Hu/PSpW4edJ/Z/2\n" +
                "2bRXs4m3ecfqHl3VbK+ailESR+GQ+pscrvh1GvMV8oeOrMQi4VEkUxlHkP4cXKo5e6Fewjj6Kbta\n" +
                "Pz/lcZJnTd9kBt7QQS54Q/ujbZjbXOJAgcP1gouYQtvOnUxF81LOP6AtvloBZEkG/eV9Db/zq/la\n" +
                "3bViMmZhQ79TVIhhRYCqhxOQOIW3AeiZg+DvSiwPjmE9d5oMlcTNsEcuBRN2FnuDLglc1KOU5zYh\n" +
                "ZzELWWeUHhLswSUJWzZf1O2oWr8nt65o7V3wQHQaySS5uyeadj1+8v7FSv53k/cjcxupCczGU/LW\n" +
                "1N0wh9LWc8TQOQqTnNejrGf6WMOvL0Jbm0rYS1H7RuoPr7KaQgZOqhKqOlM38d/f2t2VTK6DVhKZ\n" +
                "NhSlUnzFLYbg0mU49UmBFdUnLGu+DVPcRpnX/MBF9HsRAhihgvyDiuciUzPRLXZdohJc0lE+ptGk\n" +
                "Lh8+NT+FWitpCBnFCzAv2Lo+HiJvOoheVbrV64l0X63gx6gApfvVpRwnDAGgKI2fUiSQYdvuNc+y\n" +
                "IR+N9SgYd0miay2+sE3nN4mAYtOqCgOXMOHkPzcfdBdqhHdHywOzo6CvGuFM+u/RQST0KVuOpKbh\n" +
                "kWj4IML4kujRL9FaDWu5vNAey4R85FPKwOraI6WtpfYpcg23nrzSJLuimnwKf696I/AUFAsexJ9+\n" +
                "54L77W0FiTLMcO90DW/+4NelpnpcipjZpqIdeUrONEdgqrFHt2YPobey5ur1b5XtRWZE9pzzptn6\n" +
                "mOFieVgOJFUwyWDV+ryulYIRnc1FadS/dyZHRlzzKmEOU8OHHe1stS0MOSRNuJ4hXrcnDogDgMni\n" +
                "LMhFaAxtFv2wR53XxBYBVotPQle0pvy7+pYp8kdB1x0j0Mab3duNf1UyMYObeHHr0MAZhk0VxLaX\n" +
                "LW3XqJa1Uej1jlf7hB92lZHzE0C97TKYiWouQqXZy/NCu7N7SJVR2rGGv7bT6P2Pq6MmmrKaNCIQ\n" +
                "OaGsJGpN05EUl1gGjU9uc/rUU4NUXF6t1mPuUE6gesvjYXYTPdvwPh04lBt7oJqOeaqd/sG3a0Qs\n" +
                "mZrVQhENrqlLMb9GzCvlmcicaNEzXWyNeJrObx24eAaZCqa+C8A22ek2384OJZyEUjL4wF6JjhVk\n" +
                "AZNCLdyb/d9M1ZDO59u6BxU/rJdc7SeKQtG5Wg4okyS45mF0MW8MoQkb4ncH0CQSKzX3efoJ0FyB\n" +
                "PqITg+jwe38VuNqm++yTqkbVpYkzvgkALvc9MP6NcOszAMvCJzwivELGtoET5idb6XWsQhnHHtJM\n" +
                "GzD50wep2CqnMXcyXU2cqd/DhBMNKQdnPjL5A9wEWNRDtQEfdN8i+jakTVMmu4yaUSGBeStCCaFK\n" +
                "hw9+bfX3u2CtSK3IkKgDGxh0PqBAY5sttKfBdFH13G3s0bvwcxWpQb233DdVAF43pgL4bjMsWm3/\n" +
                "FnZcQLROnrcyzW+PUpx+0ujxx5TNl+yC96b/RtBLxWXkCM4S7YjSiHtVTzC2HzAlIIgM6pL2HQx/\n" +
                "bVxAjBb8se2EyydbcuRyBqnKBcrD9fkE/yIpr9fJ/ZH5MRxJkptLxZGauDvFWpaSNG3/mII88kvy\n" +
                "79HQfsGYusdPcsQ1LA3jkaQSe5hDV1vjorJuhl1fIin8LSsZpbCj/QQRb42tYmcHLNB3Yt2v6Trx\n" +
                "nX3dPPSHHuF/KsdbwpnBEZ4lm0n9z7ZNqQbnpmX/6wcwGDTcd5HysPAurMmGmJK/TXMZzzsTzpi6\n" +
                "sGH8lOCVqHXv+yMGKy5D4YtNWd0BWMYngYbza0jczq11tV9iuD5hiOP3mzB2thkgEC4okS+T0pdI\n" +
                "7zc3aUWm1iHPjD28TrnFyDNHXNfSAdJua1TVzDJhe9eGZUO9nzr7XPcnciYpcBcTmyfyYZc4COBD\n" +
                "tVIBeQakiKu88fXI6Qw6Yo/xjl7MibzWPyVwJlzczCB82UFgcVd1uvHITVf7hi74ibTvuejo2n70\n" +
                "xlNrp9Emmmd0XgjfwljTbn1SRp5NfclSUCdTvDbQ4gWa8j23SjF/wlW8DKKnGF7NDrWn54BIHbCP\n" +
                "mWUJqq7658E60dV7IqwoehxY64Ig9dZ9AF24S37ZvqPdnFw0c8FkKZmUo6YCwaWOsT7GXS9x//1A\n" +
                "ml4o3zGhynD1VlNC0cVRrXnw3L6EK2knpXC9THTairmWhOl8fOym2i+wUZGT3Y4W5A0ump1bxXaW\n" +
                "UP0kZK5/NsXroOexBNJDQwnlZwBblj+8uDw60ZrWAGQ+ttinSzI3Xvhg8rVe60e5SbQpEACjv4/F\n" +
                "feNA/45U9u/oVk6kohSHtGEbxsXnCKauaIkqAsj5iWvNjBefx2BH3/3yYWs9nMCGdWN0/CjCOOe3\n" +
                "dqBsPvC7ldrEV52KXduDdMQdhrNcb0c1MocwkKhCqK+lAvxty+yAb9y/KG0J4Mpbs94adnvt9AsX\n" +
                "KWDGobKHnTAdWhdHlERHCj5JD4i8OI1rCDJWaNqvs9ssR9Rc6l4ZULxFBH5iHrKvnBFLdxFVIxKH\n" +
                "oZ+VGMCgx0YoeZ+RrLTB/fEWwkM5j5XARw0jxuyqqZ7nkK9VM8eh6u87XdEohnckObMb5SCa39RD\n" +
                "UcBPze4ALvc9MP6NcOszAMvCJzwiFw/B9IvPD8EWKaV03/yv7Kml+WOXK5X4jhoDVOGLm6Quu2Z9\n" +
                "YYzo4XyQi5YahM0/XKcvOhbi5dZ47pCOPHUaiC94yYOnH3nxea+X6ndzCRvaDm/ivaJEx6p9korw\n" +
                "pnFKKn8T3WY2ijSrb1GtNqmuSqfoGukI81+RfnvEgH9rg8Bi84YunTgau2Zuualx9jrRoEVLetWs\n" +
                "Bo3dhP527UbXT1b86cbC0+wNG4GGkl7/4UlQpWkov8KUfNCKNbYS+r1I70zZJybH3ml5dLOMCuQn\n" +
                "BdNBIWzMD6nNuIUNhw388EtWvGBtPQDZisYI7J6RnOL54FJefzYOrzwQdWaVyfyuDTAxdQa/8AmR\n" +
                "bgKdq116Yn18kxKvccctl2FMMeiAScSsOZqmT3bxArpKvGNPoUlZnkwnt/UuhIOFXJtOrI5su1S0\n" +
                "HMju5iVQE62gprQzBuhCHTJve40OArCV9OsCZY7GhUn4HWssza3DLB6BGgYfHZHRxxkH8obOWXIs\n" +
                "sibZnHg177Q4ACUr+Ii7gaq0p0ascxm7obzGoErMUSSmptW7o8jS0WywI43iijT7wH5H3EbT2w5e\n" +
                "w4bKwqGJHWOUtyFLI/5bKZpJ10YLN6sDCyuB/f4uDbOiFHZiFrDxSu6DKDJDY7Zu0jhSHrYaL/U1\n" +
                "qSo4yk1Q06em3JW1qGcuF0zelfp6CBGD4y2Puqr72xlynbZAeBHG3xl94ya8gmPv9DpDvd44ZJV2\n" +
                "ucYNu+iHgkFi8JhWTqSiFIe0YRvGxecIpq5oiSoCyPmJa82MF5/HYEff/fJhaz2cwIZ1Y3T8KMI4\n" +
                "57f2Fh2opOjz2H5Hwk4dTvgy8dq4FA9d84gzVKnHT6RzuTIClAPjJCnihwdjhbdKtpSznWCI+7IK\n" +
                "tzFigaYdk95eH7urlRKYCgWegNmAIDFJmCScfXblk6CgoFUbrBmRdmixENRce2YZRZ34EUwv27bB\n" +
                "r+5h0qrPO1r8HC7trKkOdd2Zebb7AJGp/p9fUobKpLIM4fF8Ch+UaE3TvafnILfDGgM6KU/LASiC\n" +
                "ZS2kBdCIEzwBTwp1ZS7jF/R044FAZt05A+2M4pCWRrg0YvZTWcGDJJBh2+41z7IhH431KBh3SaJr\n" +
                "Lb6wTec3iYBi06oKA5cw4eQ/Nx90F2qEd0fLA7OjoK8a4Uz679FBJPQpW46kpuGRaPggwviS6NEv\n" +
                "0VoNa7m80B7LhHzkU8rA6tojpa2l9ilyDbeevNIku6KafAp/r3oj8BQUCx7En37ngvvtbQWJMsxw\n" +
                "73QNb/7g16WmelyKKdLq0qrGZ9hkUbFkJTpw3n7m7uY4AeuqNmhNvwhfdiLissDdTLseobJoL9uO\n" +
                "FSj6BuHyf2zBp9KEV9ngexScnPiVj2H+qgkuQqGd2UyaJjUQbh0F3xxsnSH0TTvhQnXXw0rGP/W5\n" +
                "N94lrXRO/sT493AMkZHVX2DFXRodNU3Ctogvp6fksVJ2OjXSI8NaD0IdReRGxaIitIb6glYDN1v9\n" +
                "O11ax6sKMVILcV7F1izVfbAc+pCjS0Gf5DU8qI7QLbrd3VtvWFJ6pN1x9nPnmjLXt6u2Re10lvfu\n" +
                "RRTQPuANkS2JqSPsnS1AIrrnBhJxxvP1JpuL97Wxx1f0ABwIrDPXRbYXkS5sezW+UVPf4pO7g7ec\n" +
                "qd/DhBMNKQdnPjL5A9wEWNRDtQEfdN8i+jakTVMmuymSmzptVws2/GXmWVhpjEIB51yU1Pa8km4x\n" +
                "/wlrPhDVRH4vg1ImBtKNXa3lfTXA4ODaEbFAL9IldE7XBohDPuAM0pqFkGH7+smgg9J3MFQQo7D6\n" +
                "4TCmhNLLfMbWP5pxOvs7D22phpJUT9DjWpZNfx19GHcFwFG6/dGQvUVHgXQ+rJBXWIdMAw08mkyZ\n" +
                "K+YP8wAaMsUwaCxXikhSd11GG/nd36/cMwpfgB+wLwe2rskUrQp1PLT3aTfhrqHqllfxjDSHg7CV\n" +
                "34OPccBhcW+Mpd5wZL3Y1AJFmmx3eqLT/1G+Dv8baUts5P9EKJYIeNcPkf/ckpPgCUJxzFn9oudY\n" +
                "C7bHsupPfy4p/1ycqmZrAgdPQIH/kYS+A//OoFDFrQg+Hqw9G8sAvU7PXs/VTbK+igTiBCXtaXMA\n" +
                "bCofjzJ2beEaj0Zng6W0P4A/cvFHwDKcvI7bqD9sgBB9GYkYmvPSIqyMAjkzLWlPGTcO3LdNf0KT\n" +
                "C/n21Rc0R4oJy7xM6LO7481lyDZHlqL+c70ScUmKBZDzapXt5BGsOcspOF2Lppte2teIJynoEpPK\n" +
                "aYS3ostHVnsntlbVYNq8i7M+15NWmDT7ZA7kxnWUO/5546z/gUH52qI0tdjpZudHaW7eDAJiA8Qk\n" +
                "FsS9kX76e1msD7ql/tNQUsyDVoFEUOLdsvysF/+SIirrWI3ko+2ZVSVlRfjPiJU3+E48b1bMb2cy\n" +
                "VJi56i5QGPvE3I/8AbWX0vJJ41K6/EyGsH5sWETUVqfzfYlPjxlEfgsndfjJPUEkPUSAwH6knKMr\n" +
                "hv+iviP8q9o9kYMLgWYKag3BWNkQWusNzoSf/MT5qVhxYJdt9l3d08hqx4609drZM2LiPLJo9P2K\n" +
                "sIMEeub9nAhvW6zMoeXrkvMiCtHGa3+reJFXlhhYdIVbnHlbAq7/XrXiv7RAi7+JxYhZhR1/No5b\n" +
                "FoljehRcuk1PbHnDc29mzDkNJgDY3kyoquaqbElSBMHnfA1aP5kZZj+X1l82hc79CJuVJbT/gGgq\n" +
                "gQzF4NRBhzN7puL7YCBiKoMz6hVJEDiqTf/PRYbHju9VwHqgQpJVNeqCKT6L/Df+Wq2l/Iswpg7/\n" +
                "FldLSUnFgtvlcQsyqzUUo0jyerVZLikw7YVr7PiGUHYteEVwAdY7SW5PP+nuaA6zLI934oP2G4/P\n" +
                "OJCiemfmGK6ret8wN5/hKbM5ZTnUFV2q7SpM3pdFGvIShBbxFz2cgo4oZyc8Qu3OOXCWM8/0xX0h\n" +
                "k/XxHmThUhoUIvRksH8YFE29SDpBHC/BcEFYROU6whEEKbRQAavF3kGV6qkJZrHBw5cfM8zq4FvJ\n" +
                "yiXGMw9sVauPvPVuYYUNHBdVygTjoioS/05N9Jmur8IsTB7jGcWAJ+xnDBzudZIZJUs0Y2ZD1NR4\n" +
                "WT+uO+gDxzb2ihSifdL3x7k7yUrbFaX7JP9NRt59Kvz2ko01up8f4d/xZd+hncwVrJ54czzRZfiW\n" +
                "p90Nuq8Qc4hwHiMpszudlKgKe26smX7Mr+aiO/CcWnAPXiEf7mDBGqHmZEM/VUwC8rkqKwzzGwQf\n" +
                "2+cqjqejyPT85hbBG9ICyY0TF0x7jPaRSN3mQq79MH83YMh+l1f8+8/1d2J0nsBbWmLAI25KMAqB\n" +
                "I8gli9BJ+7SJJgRbZ9zbzvaz2NVLMQ5+boWzTbHoadmcWQCqPkvrKS4TqL0Uiqo952AT2LZsCCmt\n" +
                "s6bc0EdmeNoP/lMZZjnm0yzpj6urYrPSRncOTSjaPh7cF/6kVXo/BocUE5aTkIbfbpihCWDPweTX\n" +
                "iASX7pM7qf/vCEwKn3FBM4OrtgZw7YPGOtG2BpqdqMOrleb/xIWjTeATxm6Desps0RDjByMLqMoK\n" +
                "rZXRCDuEvAq2MG86Y/421uId6ThSXcTycfu7dNuvThUcgJDforFpacnvivrQ7dt1oRKzfFHSrQJu\n" +
                "1WK7yux9ymvnwVgtl4Oers2wY1HrKvRi/Nkw9mkBwExoVzCznsJCXkrkRENvEd4Wkls25k3JfETq\n" +
                "HwAf8ftM9vB2saSQWgynfzSt+F+I2ld4RB8qqZjsSFwhQLFLQ6WQ40rU33eX4lUECRZEWLGMNrqm\n" +
                "rbValdfxScmlkkVgX1JSVyxcz/SPJd7KyzYMv0jJttbCgbYv9aPnPSgGD3GC08uLe/eYsRDUXHtm\n" +
                "GUWd+BFML9u2wa/uYdKqzzta/Bwu7aypDnXdmXm2+wCRqf6fX1KGyqSy3umCOtPPBgmXM+G5xqtL\n" +
                "WhoDOilPywEogmUtpAXQiBM8AU8KdWUu4xf0dOOBQGbd6SsT0c2UeCM5b4+ZoVF5IiSQYdvuNc+y\n" +
                "IR+N9SgYd0miay2+sE3nN4mAYtOqCgOXMOHkPzcfdBdqhHdHywOzo6CvGuFM+u/RQST0KVuOpKbh\n" +
                "kWj4IML4kujRL9FaDWu5vNAey4R85FPKwOraI6WtpfYpcg23nrzSJLuimnwKf696I/AUFAsexJ9+\n" +
                "54L77W0FiTLMcO90DW/+4NelpnpciinS6tKqxmfYZFGxZCU6cN5+5u7mOAHrqjZoTb8IX3Yi4rLA\n" +
                "3Uy7HqGyaC/bjhUo+gbh8n9swafShFfZ4HsUnJz4lY9h/qoJLkKhndlMmiY1EG4dBd8cbJ0h9E07\n" +
                "4UJ118NKxj/1uTfeJa10Tv7E+PdwDJGR1V9gxV0aHTVNwraIXYRmpieHE40GR1348sVZLJwlVIJA\n" +
                "HmGAhoDE8YFeHwLGVF8nrQsFP3FskzZXbzr9XVrHqwoxUgtxXsXWLNV9sBz6kKNLQZ/kNTyojtAt\n" +
                "ut3dW29YUnqk3XH2c+eaMte3q7ZF7XSW9+5FFNA+4A2RLQb62eKZxHy8IQzZbgKTZGiG8Pq2KdxP\n" +
                "NcxZGBYCll9d5qT8I8+2r4fXOConQYDLsbYXkS5sezW+UVPf4pO7g7ecqd/DhBMNKQdnPjL5A9wE\n" +
                "WNRDtQEfdN8i+jakTVMmuymSmzptVws2/GXmWVhpjEJtHCV+L8ZpQCbCJYw+hsUYRH4vg1ImBtKN\n" +
                "Xa3lfTXA4ODaEbFAL9IldE7XBohDPuDvUbFBJpaLAKjY0b3xdXQpo7D64TCmhNLLfMbWP5pxOvs7\n" +
                "D22phpJUT9DjWpZNfx19GHcFwFG6/dGQvUVHgXQ+rJBXWIdMAw08mkyZK+YP8wAaMsUwaCxXikhS\n" +
                "d11GG/nd36/cMwpfgB+wLwe2rskUrQp1PLT3aTfhrqHqllfxjDSHg7CV34OPccBhcW+Mpd5wZL3Y\n" +
                "1AJFmmx3eqLT/1G+Dv8baUts5P9EKJYIeNcPkf/ckpPgCUJxzFn9oudYC7bHsupPfy4p/1ycqmZr\n" +
                "AgdPQIH/kYS+A//OoFDFrQg+Hqw9G8sAvU7PXs/VTbK+igTiBCXtaXMAbCofjzJ2beEaj0Zng6W0\n" +
                "P4A/cvFHwDKcvI7bqD9sgBB9GYkYmvPSIqzavZOCrhOMIkCpo3+54T5Wh4xYZRF1zEkbkO+Gj4Qs\n" +
                "E1DJTp6MXhQAHfrZ2NkGmnYJou8Qye5umbt6p9LsSjgUywDQ8Fb5vJEVJVMiK8gJ8Gvpxi8apLtl\n" +
                "VrpT4YpzNJu0ssjdzbqhZqmPTKZgONl1eqjEiplCQsziexifMkn6kltTCIZmMSiW8ivh8Ka9WOHQ\n" +
                "4cJyA9rWnubugBW9piV/YaTZT0lROSafM2Xuw1aO4yExxG6bCvUKQXDCIEwoYX+TRPrS81wXvDtR\n" +
                "/L+8bWm4QJjfR3Ay0twXgUZjBf/VWu4OQ3JWXXKGlckLZ19fA4mgJfvBRTrcPz/AuHXFHps2tdvw\n" +
                "VO6dDE4XENuMUhnTVplhsln5s+4CK73kvXur7jKBvpDRXhz5x75XHZo27/caeBJXEI6quc7NCQK6\n" +
                "luZESwVppwijGKV/QhzYm3u7jmS8UsxpcwoAH1OJTK0tcldsB2uza1MR3Q57KwudeAVjb/lM5EO7\n" +
                "EY7RsteKHzdiTNK7IDsjtFN6bOlZsEvY3gaYrMhxIWYC3w1xjqqVX3g6XLgUZ8yM6GXwMcfqmIm+\n" +
                "b38nuApv3Uf+NYewine6hTOSp35GlmaHiHn3LerE0k5JyjziZzuY+4x7MconyojMfKi+Mqwbf28H\n" +
                "bP5oKDMZ9VJ3AZGQl6dkVh2OVNShdPLEQh56n5svKlx6H+TAbtYVYgNIkP1FdFPDNIemisy6Ocxf\n" +
                "jl9HTF9WC2u+xnegbpeB57DF2OUu6FqW+eaG7Oh/nfbwocnNLDyuFhnbmFLBwuYPr8iyfCnr1lCS\n" +
                "jS4vQBTJVy/DM/ZtVXvkltAyHfgHW0xVHITUu6nTV0JmZvyLuqaK5oOYQtt2gKJAh0NhYzMiw+p1\n" +
                "EY4cC1STLD20rGMDZsd5bbEt9f0TL+hTJJZf6mXVU+6UW6nTI8afvFb1qNZ7SgShM+C/gRsqEaMA\n" +
                "JGkc+kPwKIYea6k6cn0BILeetCsn//6Aq/0S9DBIHFAYBU/7aKuRidvFtyHYK8WIb+a/lhXCmAyK\n" +
                "Di36PC2nn7V27JfiCmTTNNmwSCuXY2MK/G3wlN084mZ4ElfdkSwxgqaBjTi4tikZYm87cDwm2bg5\n" +
                "04HuebKouOTKwZQnEw8PM9Zy35eX4LRItEQ+TZjsiMwm14gB438+nXQwStjFxpAaQXD+OFzd4P2m\n" +
                "gBXNnu7D2qrI4pdS4Tg+HU3GBLe1xOjZGyYqmYQXeTj4jyzpEqZHfhQxcrl74Y8/wx647Jut8PSL\n" +
                "axxixnMQKHNui4OrOk+jXaYS47DIDrXx52zJdQVhblZuBlzNVZQ03vrFT1iow0iYcXEXz3nQjMEy\n" +
                "Mzx88WozRK60+vb9xjP7XStrgqWX+Ve2nKnfw4QTDSkHZz4y+QPcBFjUQ7UBH3TfIvo2pE1TJrt5\n" +
                "n3hCOJLDjSCoqLQdqxW6Z7w9UfmAi6GxstQRVendhRoDOilPywEogmUtpAXQiBPJugKJGHlzomf1\n" +
                "tmtMWlMDs1en1Tc4jIOQJ38xiMaQtcT5qVhxYJdt9l3d08hqx4609drZM2LiPLJo9P2KsIMEeub9\n" +
                "nAhvW6zMoeXrkvMiCtHGa3+reJFXlhhYdIVbnHlbAq7/XrXiv7RAi7+JxYhZhR1/No5bFoljehRc\n" +
                "uk1PbHnDc29mzDkNJgDY3kyoquaqbElSBMHnfA1aP5kZZj+X1l82hc79CJuVJbT/gGgqgaknIwzc\n" +
                "hnLwECu48j7xCFhiFZEw824QT+yu9cXYaDi7K1j0Vih5FKVKoUHPmavzyNYROY7Mc3o/8Ag0fk6S\n" +
                "LDokzRdxd2vHRp4z5O9GyJKyVk6kohSHtGEbxsXnCKauaIkqAsj5iWvNjBefx2BH3/3yYWs9nMCG\n" +
                "dWN0/CjCOOe3os4ku9hDkIKHS4njrLDc9mIG/fsIzxPFutGsPrpQlghDQB2p4L5R/CTLcnWRq7cp\n" +
                "B3+VXwRsJ/7+bREMcGSmlD0qVuHnSf2f9tm0V7OJt3nH6h5d1WyvmopREkfhkPqbHK74dRrzFfKH\n" +
                "jqzEIuFRJCC418EaIN1nO6sHe+GBtnovm3lXDzoWNHavkWMlFqoztP7LV67lF4ihJSZOPqnscXRM\n" +
                "lGUOOweIECBSrUyEOCrBo98kqrZ5yaacsNLt99n4xeFu7bnQRDoh7Z1DKo0GG57UhtYTM0KboMAv\n" +
                "4OgLJdpjE/9vNjvFdum6wscql7Rh6WjYM4mARuQZu2ou8tWiXrDyn6Gl9b+C0kVzvvZBsCu5EA74\n" +
                "/c+DKwaXjoxULIyHMjbwIrePYOnW75aL7x8921js//q9y5DHFrZdNPhw8zGa/JmFrpY7drbToACU\n" +
                "KskFmGg7FL+1pbannNRWw+fPbyKJ8ctOYkLhCjNE25+VkI/gDODTBiOiP5G7l8uAf9Y9a3vxRX8S\n" +
                "s9mq8GvsuzyasZk4m58oa0AicxbwV8Z+NgvIFTUT3ppznxLRWJe0F/7xgi2Yt0+0BeWo4irlfkd9\n" +
                "CLxR5QO8oHGR/t4sCoiANN1BtHRjUZJKISaIcK/Nczd1o+H+urg+CGNT7gdWuLLxInNJ0Oe1u+SY\n" +
                "vJH4/G5zZKrfUIsyBhYaeFglYfw42l47Fpzyz3E+wJjS3UivJw0BQDTpBVa1ExDgAnQVB9frbWUP\n" +
                "WUFHP/YlSkPON4tC9QFBCqxxMfYrCm7EA1Q5EQDaehflh1g7TCp7kYcAc8YRvsLN/dxxC/pr4igs\n" +
                "t32hshyToGNbOmKEOXRIj+7ng4VPuBELmjXuznI+gZ+wb03RhZLBpLmzZnxkVCWzQaRdUqp3YVfE\n" +
                "cQeNv0dt55zx45MB3AYwni3IuPfgVid9j5wos6R2ruV7TMZUfX2FTkq+BQE+4z0JiVnV9eFfZAeL\n" +
                "ASn8OEKakEoiRMxmJGNhBQaQu6j+HprbJqn1UQzapi1LaVGoLxGsQgBg9rO28okZP5IfgVVhZpWT\n" +
                "dEY3v4m79pYWbiI1ubtHxG3Yh/9fsjzRsQhb3eCsvfnO0JDOE75U2l8vdSw3p1d5L/br/7NLXPbI\n" +
                "mLSMKac7JXhurAubNzDqAH2oY8+ne3w3QVbjDSCwUhqkJz/fEPTan+d83Sd1VrwfH0X2Zx7MgqPM\n" +
                "ItIo5BvSI/7DnnyHeDxHepL/2zFL5CDGTYBdWf6tqB6q17TibYm334uDcwIDC1XrUCM2L12XhcDN\n" +
                "JGbNSQAZOO5cHRaH9z2JYIDbDUb43Aie76OldZcKRQesTMmy7UpPuq60skO4hh9XBBK87S2sg2Db\n" +
                "KDKij2soocKYDIoOLfo8LaeftXbsl+IKZNM02bBIK5djYwr8bfCU3TziZngSV92RLDGCpoGNOLi2\n" +
                "KRlibztwPCbZuDnTge55sqi45MrBlCcTDw8z1nLfl5fgtEi0RD5NmOyIzCbXiAHjfz6ddDBK2MXG\n" +
                "kBpBcP44XN3g/aaAFc2e7sPaqsjil1LhOD4dTcYEt7XE6NkbJqExiM/inPHcuaThoxaq6b50G7Ci\n" +
                "ZhyRy4RFnOhKNrgpTPd060X/aGY3m+AX3XlHts/vbTzw1xz+w/VA3deIcRtmr9PY0emqcs6/94Yv\n" +
                "RmCO5ZmR6XS+s8dOYOB7IowMaKWbBSZivj8Q/S9zfqYvb5gWYT/ChbccZKH2cTJzjjmZrO3j5whG\n" +
                "qGOrz8wDypXYVd6GrJwbWNgv3HgV4D5H5OMgoQlYEmXcWhV81ZPvrd3gdRCi76mUQOyhMlLbo6ff\n" +
                "ddXlNN7gkcdhxqM7m40pOEtKrjGPsExoeyVg5U4Kqf3zumMxTACPGJqjL54b0IoK6EkLwRFgFrQU\n" +
                "DPWjKOOJ9788SbQMrpJ3DvIOf2cFMehB+Xb2LWBwXO35oMM07esElYADwHhqSUS9TY9e2Zx+GgxM\n" +
                "UockL0begFeBggXoi6uNKTCMb4e3COGH8FKJjWrInRW1Z0OU1SPIfdFK161z7uX5+iU1kBfI+xl3\n" +
                "YM69Pur6vnbxKAf1bGzLQnBLCVldaFQT77Dr1bqwWq7sEjFt2pjdGClrDaQ4SKEm2D1GPJAtJ2if\n" +
                "g0sDEPRE5Rl8yj/4k3DE4vIFlfhDYxFZVO5ljXXqdRGOHAtUkyw9tKxjA2bHR6IXJQMyG762dLI5\n" +
                "b44cCm2M8IMCNofukbKE3h5ym/d6qOo+vRLNI26N6qY3vRuFbWBpX0buvdgW50rAjRJlk/Xv+jQW\n" +
                "sAnmoNVAmEfQ2xWEv+9VxYsklOqfv10eJiEggHWgO7EtJmTj73t29Yl/UjsbJvLQ2lBs579eX54a\n" +
                "J6hIkP1FdFPDNIemisy6OcxfazREHFGipJ19+IQo5g/tejnnC2BvlKf8gx7cb/ElUV0Gvw+I6Aoe\n" +
                "M0SLjfjIpiwPgI31+mFIcNW8zAReCUb+Uwc8fkPvuLCjYLEY50b5div0OatquSUSdWGLhjyYt8OF\n" +
                "Xl7XuCQJp3Yz8Ox8Jbd29pG5L4rCkD8FjggOZlPXZIOGQdea/Cvh9Yaj7zpX7pgcmCCVemasDgdv\n" +
                "X1R1LQ0whk4CyclZKjaMrrMxIDUddc/8Z91su1kKqzpfvyeU+gh4Lh7OwM0zoUEXAkQAp2SUnsib\n" +
                "wVpdGrGVju/WYMqCODxLUl+46acKYTyFCQtQRTpwF+7vP+7IVFSbCVXevbWX9B0Zi4Cufs2qeA0v\n" +
                "sk1ySyBRbHTjZyOv1ebU+1ETViJNz+9tPPDXHP7D9UDd14hxG/e5plt7Ddx9jOlJengOx/YiKutY\n" +
                "jeSj7ZlVJWVF+M+IlTf4TjxvVsxvZzJUmLnqLmAmiM9TOSYY2APYQiYuVqFrTfBzqJBtqRMlb52o\n" +
                "ub1mMDF1Br/wCZFuAp2rXXpifS2Ag5QVj4f+s1j5XD/NanGD6j85libYLWzVZO9ACnpnENLqd2UG\n" +
                "7swJJczmN9NcNwG/ZwzI9U97nJzFbKumpU3GVoKvzOZscSHHmbBW37Oo+8RtCJ3bY998ntviVNXB\n" +
                "SX/n7ojnPJ+O/cWc4rsodzVJuvJywSGQCbcqjpUU9ageJz5eLuSxW7H9ovrhSmNxbcF9sXOPEo8p\n" +
                "wJJ6ae+0IpGRuyywD31S6Wcfjz4TPxGjqgUihcEk1SgwAiKfVGOBiI12UpsMp+SjkAWYxzRYM0iM\n" +
                "ZkI8CPt/Bof8TiPjZSyo3MGbBY21426KL74MlYeMYYwUDrZmZUwp6LpOgJvBTN6oG3A5Lbe3irnX\n" +
                "xO3kvExuoSjf34JyUVjuC78J9lvkTja1ekwYI/31e4sIKKr9qVmSnUWkEr0FVz7LL+0jJoIwL/Ul\n" +
                "UCZsU37Y6f17+yWUpI1Z9CUU7wc9kNDEbL++OBO0HIQRV3cfKM+rOG0cFVRUhXmym/H/1uj2xo+g\n" +
                "IQx5RrK70zxfPa5LViT6v/59GAB2yt4KJbNDQGe+7riuS2vw72IbjQ9mHByfjULvje9rEbPi8rM9\n" +
                "6RRrSEqGhdL+Ymonpo0NAOiAa6j+2Hbspm/IpUWowPyM2OGdLkDNLrIxmTht0ZOptxFZmCdZDuku\n" +
                "CsJoR0HZ+v9bBMXZC5qpxQqxHUkDWJlUdfTbyM+Hq2v3URGuWwTpDM3j5m7yjzc7Od72Q79tztq3\n" +
                "8IXttlvmLoANHBhMT8hzrAyKHy/0xsLrKu7ObCGtKwbrXzPv3YesH12Pwq0LjIYnWZxHbjoUUGvX\n" +
                "41jyp1zLKc6A5PnyGifZo6fyRRTUu2osrZyRMaaNgUHfe2i6WKaql6xBxj5ttmke0ntq7NoeMl+W\n" +
                "UlQkbcZ5qLPHw/7/zH1NyFRl1SftPs8d23VCfYOIsCzJSppcKaYGrGhAtt+apZt11sy7fuNo4RhC\n" +
                "iqwvH7WwDrwtTwAKBvaJg/cKOnc/i/NXjmK5hR92f4t+YQd9vHM2tXX74jxTqxwsX2ESJkyhSsyd\n" +
                "sF3Hy5IZZS3c2I59r7TMxfclcxdxOqeRHNh6wAN1CYFhQx2H57L8HpE9OVDHYtsJijcOp8v4FIH7\n" +
                "Ool0RhYmqMpN2HTLVQaDABAssEGu6Xs1VXwE0Y363EQbcCsyV3moG2Ptbi4DTbTNfBj/m+6IqTkM\n" +
                "x/WUaZWV1dSV8bYOyscVdAr5bp6Tq8mLq/VIwuB4Zx/mNO/pqvq+FbDM3CA0mx3lPSluSji/rfVK\n" +
                "4To1O8BFgGxjwVHxSjQg+svIUf9Ari/bxBs3cHjis8qVwc3Nw/6613ghrkXR8/nXBZAubWBBtqZy\n" +
                "jVdLVwucBqVdFqdwgyrFUCVDWLUKarUiqvSEtci1zapZuo0wudn6BezorQ6jUWYFB8sA0PBW+byR\n" +
                "FSVTIivICfCExlXOIH243odp/SWn5gbRgUB8oXTeQZtSfRb4SMjXYzsAf7YM8PLk3oX5XEkfKR9h\n" +
                "7ZRVQlSkxzYf+OZUDS/ooNYYmPP0Wfa7kvB0R02uy49Xk0RgoNMMVNbnRo1cWtn8F3nLQmnj04ht\n" +
                "OIrwSyLaUhoUIvRksH8YFE29SDpBHC/BcEFYROU6whEEKbRQAauPBOQDXnCWVgK6hnGLV7SRPWHX\n" +
                "sRE4+OzxHLQVC96CarKe9qDFZJk6TPWu6F2zUILs/6geXIjwN8AR3c57Hi6IqeV01NG/fANlO0YH\n" +
                "D1IFbIv19jM+0Ik5cmrB6bLivOg74psm5O++YZIx2NePbeQRuvu/HOu7MPiO+dmVrOz2VZ0KioVj\n" +
                "YkZmSlwqJyy0pZwCQ8YJcp7Grl/HSJgdDILGqu9jv75mMoNnE4WG15nzO+PQ9lGJTawAqrUNtcQ4\n" +
                "eIQLMmMwbXsHv0+KU6UPuB32IckRSO8HfZPFgUbChAu052ZkyiBlnf7uEpFXktb5eLalHqQdiumo\n" +
                "WEHbZdHveJfrgkZsz5JdCNRkAGvfLu1wfYs5uCBXKhX4wC9Vq3SEds00aCMbpUexzS1hVI1KTYng\n" +
                "0ntq7NoeMl+WUlQkbcZ5qGXrOMhBttT+Nd/4fo/HSs8W23DslxocHh5giF+3wfzAQRblOG7nFWJK\n" +
                "eqAteNCONICWaLzBPA5jLRvKZnnJ6VZqlmso+nDFW8078A8cYmRbKbM7nZSoCnturJl+zK/moltU\n" +
                "4C25WgLE2tZtiFhI3yMq6pvwnZdXPYun6yNQzeVFLFpt/xZ2XEC0Tp63Ms1vj1KcftLo8ceUzZfs\n" +
                "gvem/0bQS8Vl5AjOEu2I0oh7VU8wth8wJSCIDOqS9h0Mf21cQIwW/LHthMsnW3LkcgapygXKw/X5\n" +
                "BP8iKa/Xyf2R+TEcSZKbS8WRmrg7xVqWkjRt/5iCPPJL8u/R0H7BmLrHT3LENSwN45GkEnuYQ1db\n" +
                "46KyDm8PFnUatNOedhdiYX5zSObu55/QfPhQeUNP6KMXHKIb5pTzMUF1+bR63k/l2VvqiaMAF6rN\n" +
                "zzPbuhoEA6DiuaXFLydgk6t4cWwZ/JNhu9fH6h5d1WyvmopREkfhkPqbtRgyJ+OLvbaYj7dCuV+W\n" +
                "jHBL5ileCbJpSUz7LpTv7Cx1YZe9AGnHE1ybxZ1rU/DRAwyLdxmuq5iCO9xcDQKqt/+/l2A7AerZ\n" +
                "6JnFUU0FUOMdEkfWOV85jPZtAXJhlZ57ZUMyfV4irao/nRUPLDxCgeJR6/bERF2FoBVeUBQQhhtW\n" +
                "TqSiFIe0YRvGxecIpq5oemfWR/x0nM/41Abo6jORYDrBSpkdreJXtJ/GltCefK9T4gpz2CQ9n/lV\n" +
                "2ImW0qL9QYb2k/avZuGuSqCH+qMeVF/V8fqGaMDj4pXPW4542PO5tGKFsQHXWcBKuDb2zuDZaHnq\n" +
                "XpP7bDHFp3W/BoVLD0aOFmbY53UC56WWgoY79RIyN97D5fI8WL6EeFBY40wI28H78HgFB6plFgA4\n" +
                "Ar/nBClRdieWxf/kFTkglXfa8alj7M9/NivPl/w39u32K70fitf1y5lYB3aVgsbR6MPaUKp+tpPA\n" +
                "9AI5JfUxpU9YsRzfe2i6WKaql6xBxj5ttmke0ntq7NoeMl+WUlQkbcZ5qLPHw/7/zH1NyFRl1Sft\n" +
                "Ps8d23VCfYOIsCzJSppcKaYGrGhAtt+apZt11sy7fuNo4RhCiqwvH7WwDrwtTwAKBvaJg/cKOnc/\n" +
                "i/NXjmK5hR92f4t+YQd9vHM2tXX74jxTq4Zvzwr8DLqVyIrAorMmO4gZZS3c2I59r7TMxfclcxdx\n" +
                "OqeRHNh6wAN1CYFhQx2H57L8HpE9OVDHYtsJijcOp8utbU5h2OKtfjFqFHcbLtlLVQaDABAssEGu\n" +
                "6Xs1VXwE0Y363EQbcCsyV3moG2Ptbi4DTbTNfBj/m+6IqTkMx/WUaZWV1dSV8bYOyscVdAr5bp6T\n" +
                "q8mLq/VIwuB4Zx/mNO/pqvq+FbDM3CA0mx3lPSluSji/rfVK4To1O8BFgGxjwVHxSjQg+svIUf9A\n" +
                "ri/bxBs3cHjis8qVwc3Nw/6613ghrkXR8/nXBZAubWBBtqZyjVdLVwucBqVdFqdwgyrFUCVDWLUK\n" +
                "arUiqvSEtci1zapZuo0wudn6BezorQ6jUWYFB8sA0PBW+byRFSVTIivICfCExlXOIH243odp/SWn\n" +
                "5gbRgUB8oXTeQZtSfRb4SMjXYzsAf7YM8PLk3oX5XEkfKR9h7ZRVQlSkxzYf+OZUDS/ooNYYmPP0\n" +
                "Wfa7kvB0R02uy49Xk0RgoNMMVNbnRo1cWtn8F3nLQmnj04htOIrwSyLaUhoUIvRksH8YFE29SDpB\n" +
                "HC/BcEFYROU6whEEKbRQAauPBOQDXnCWVgK6hnGLV7SRSXCXDVP1I04UIKtxHf98rgJoqD/IAl+T\n" +
                "pLitMP/srgFZZH9ip9ZcsIGKFU5ddydFC5NT4ot+CN47vyrsE6o8bs6xKjX9h/wssUiskedR/A7E\n" +
                "xWeuHR8yeOMQTUgBVwhslQJoPqceTIeRmCMybvFE8FbZDYj+OCBpgTg0ZV6iEJ8vYHwUwdRDPjTC\n" +
                "hXdEwQCdblSKPWIY/Ce9yXNQmyCB+w+eYyI3Ekee+u+fOsHVEAWbGZv77JsBw5a2RlbvKX/ZVjza\n" +
                "mCt6aqIcNtdQ+jBMeJGlPvarOlZdD0VgF3U5F3Ky4zuyWFrPxrjxOrp6NRGPGJqVuVF/n0TSGyBk\n" +
                "V9NRoSHWkh9513JEQWMrQg9ss8VZgf6YLXf1IEWYyrE/0KxiUKLdgcrOxZcB/LC6UP7lpnEXz3nQ\n" +
                "jMEyMzx88WozRK7IU4SiCoy73Tn1NuHzBO1TYd2Zb9F42WljT8ZTC8WpTgUOAT3snmjVLqLBiAwb\n" +
                "ElLvTNknJsfeaXl0s4wK5CcF00EhbMwPqc24hQ2HDfzwS6UPoHhtIrBPI5A01UzgwLHYYw4MG/o7\n" +
                "VVLcMhrKB6tjaleA8gCQtBpqzbD6k11pqoZsb/7mDCI/8O3cM5CtvuUqE7uBVKd1x8Rj+ji0l0CJ\n" +
                "5omjuoeRQwvr1mni3lqCWpAdz99NGcYXwLS8pNC6wBfqfMR6WMLHtPYtHvBGcsz/kI6WKrmRtt8m\n" +
                "LN5iFfAHjhWtUZN+Tgj1KAppvXtGYtKT1YgrmBdNIsdK18L/FLxUXRa59IrqLzzcxVgX0+lxeMyX\n" +
                "MoZqsOI0nC6Fy4ErZ9Fe1CxL1/BepzFju/CHkbwrj0zbNn6V1pM5+JLCj37lRW40WmZbVmLBfUd6\n" +
                "J7eMCEPbjgz2s20uZqEwsjmqfPLep4Hmq6iBWh7lLYFd6sQROpuNliCSPapmSuySaJ17zyIvwXBB\n" +
                "WETlOsIRBCm0UAGrdMPIMDQfLAETVwpjfPrpXx7vLQCV8RdJF3z/34tWAQo4uO+iD5ymGyaQmhVB\n" +
                "Fwaf4n165TH6i9wOdC75tLGxtKLR0S6RWpy9yv0Nmgm4bK5XJS4d7G5DaiZ8IV5Q2Y+abTnLUAb6\n" +
                "JA+6Zw7QKOkMX8sA0PBW+byRFSVTIivICfCkjl7U7hG2IyAmK2wvZKWVUgys4XcF20VjJapyoLI4\n" +
                "pOErMkY84tJW5+GXIvjhGq1oiybdg7HlHAWarxn1ptz4cmr/0o3tkFbgMZrKcP5oP23bFI7S/H1V\n" +
                "5Bd2/b7YocdRI7eA0XBFoXpZ2tY1oAn1Gdq9toSvvWBmzAchW8B9qVzFk99FIKnag0bG513z5q97\n" +
                "Ec/s2+7Ix6iZ8IOVgSiJlp4hTFi7NWvCRqeQWt/vOtkQaopDIQydoLY1SK73bhvMuD0JbUKZpbKX\n" +
                "tYrKsvlt1/HQ6g7ACkC+E89x4xpdh08ujt05X9kFIFOUU+JJvPTUx9tsPNesl+pexWrw7Rq1RQfq\n" +
                "3dUWe+d7TNy2nkGPrlCi3YHKzsWXAfywulD+5aZxF8950IzBMjM8fPFqM0SuyFOEogqMu9059Tbh\n" +
                "8wTtU2HdmW/ReNlpY0/GUwvFqU4I0cnC4Dn/M8IeXVJ9SEQD\n";
        String decrypted = crypto.decrypt(encrypted, symmetric);

        System.out.println("Symmetric: " +symmetric);
        System.out.println("Encrypted: " +encrypted);
        System.out.println("Decrypted: " +decrypted);

        String symmetric3 = "Bos0HSxY4HWrVwEZaoywbAnP8a0BWExEfl5pyHULEXQ=";//encryptedCommunication.generateSymmtericKey();
        String encrypted3 = crypto.encrypt("sofianna", symmetric3);
        String decrypted3 = crypto.decrypt(encrypted3, symmetric3);

        System.out.println("Symmetric: " +symmetric3);
        System.out.println("Encrypted: " +encrypted3);
        System.out.println("Decrypted: " +decrypted3);

    }


}
