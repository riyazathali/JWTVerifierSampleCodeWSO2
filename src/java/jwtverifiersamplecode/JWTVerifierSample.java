package jwtverifiersamplecode;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;


public class JWTVerifierSample {

    public static void main(String[] args){
        JWTVerifierSample jwtVerifierSample = new JWTVerifierSample();
        jwtVerifierSample.getClaimsUser("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }



    /* This method returns the end user from the claims */

    public String getClaimsUser(String jwttoken) {
        String claimUser = null;

        String[] jwtTokenValues = jwttoken.split("\\.");
        if (jwtTokenValues.length > 1) {
            System.out.println("getClaimUser() - token: " + jwtTokenValues[1]);

            Base64 base64Url = new Base64(true);
            String value = new String( base64Url.decode(jwtTokenValues[1].getBytes()), StandardCharsets.UTF_8);

            System.out.println("getClaimUser() - body value: " + value);

            JSONObject body = parseJSON(value);
            if (body != null) {
                String email = (String) body.get("http://wso2.org/claims/enduser");

                System.out.println("getClaimUser() - email: " + email);

                claimUser = stripCarbon(email);
            }
        }

        System.out.println("getClaimUser() - claimUser: " + claimUser);

        String user = getNewClaimsUser(jwttoken);

        return claimUser;
    }


    private JSONObject parseJSON(String value) {
        JSONObject body = null;

        JSONParser parser = new JSONParser();
        try {
            body = (JSONObject) parser.parse(value);
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }

        return body;
    }

    private String stripCarbon(String user) {
        return user.replace("@carbon.super", "");
    }


    public String getNewClaimsUser(String signedJWTAsString) {
        System.out.println("getNewClaimsUser() - signedJWTAsString: " + signedJWTAsString);

        String claimUser = null;

        try {
            SignedJWT signedJWT = SignedJWT.parse(signedJWTAsString);

            verifySignature(signedJWT);

            JWTClaimsSet claimsSet = (JWTClaimsSet) signedJWT.getJWTClaimsSet();

            claimUser = claimsSet.getStringClaim("http://wso2.org/claims/enduser");

            claimUser = stripCarbon(claimUser);
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }

        System.out.println("getNewClaimsUser() - claimUser: " + claimUser);

        return claimUser;
    }


    private boolean verifySignature(SignedJWT signedJWT) throws Exception {
        InputStream file = new BufferedInputStream( new FileInputStream("/Users/user/Documents/<APIM_HOME>/repository/resources/security/wso2carbon.jks") );

        KeyStore keystore = KeyStore.getInstance( KeyStore.getDefaultType() );
        keystore.load(file, "wso2carbon".toCharArray());

        String alias = "wso2carbon";

        System.out.println("verifySignature - header: " + signedJWT.getHeader());
        System.out.println("verifySignature - algorithm: " + signedJWT.getHeader().getAlgorithm());

        Certificate cert = keystore.getCertificate(alias);

        System.out.println("verifySignature() - cert: " + cert);

        RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();

        System.out.println("verifySignature() - publicKey: " + publicKey);

        System.out.println("verifySignature() - algorithm: " + publicKey.getAlgorithm());

        JWSVerifier verifier = new RSASSAVerifier(publicKey);

        boolean valid = signedJWT.verify(verifier);

        System.out.println("verifySignature() - valid: " + valid);

        return valid;

    }

}