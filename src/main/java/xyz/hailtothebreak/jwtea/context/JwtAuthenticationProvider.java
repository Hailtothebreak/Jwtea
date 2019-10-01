package xyz.hailtothebreak.jwtea.context;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.Verification;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import xyz.hailtothebreak.jwtea.configuration.JwtConfiguration;

import java.util.*;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final Map<String, JWTVerifier> supportedAlgorithmVerifiers = new HashMap<>();
    private final boolean verificationEnabled;

    public JwtAuthenticationProvider(JwtConfiguration jwtConfiguration) {
        this(jwtConfiguration.getAlgorithms(),
                jwtConfiguration.getIssuer(),
                jwtConfiguration.getAudience(),
                jwtConfiguration.getLeeway(),
                jwtConfiguration.isVerificationEnabled());
    }

    public JwtAuthenticationProvider(boolean verificationEnabled) {
        this(Collections.emptyList(),
                null,
                null,
                null,
                verificationEnabled);
    }

    public JwtAuthenticationProvider(List<Algorithm> algorithm,
                                     String issuer,
                                     String audience,
                                     Long leeway) {
        this(algorithm, issuer, audience, leeway, true);
    }

    private JwtAuthenticationProvider(List<Algorithm> algorithms,
                                     String issuer,
                                     String audience,
                                     Long leeway,
                                     boolean verificationEnabled) {
        this.verificationEnabled = verificationEnabled;

        if(verificationEnabled) {
            for (Algorithm algorithm : algorithms) {
                final Verification verification = JWT.require(algorithm);

                if(!Objects.isNull(issuer)) {
                    verification.withIssuer(issuer);
                }

                if(!Objects.isNull(audience)) {
                    verification.withAudience(audience);
                }

                if(!Objects.isNull(leeway)) {
                    verification.acceptLeeway(leeway);
                }

                this.supportedAlgorithmVerifiers.put(algorithm.getName(), verification.build());
            }
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(!supports(authentication.getClass())) {
            return null;
        }

        JwtAuthentication jwtAuthentication = (JwtAuthentication) authentication;

        if(verificationEnabled) {
            JWTVerifier verifier = supportedAlgorithmVerifiers.get(jwtAuthentication.getAlgorithmName());

            if(Objects.isNull(verifier)) {
                return null;
            }

            try {
                verifier.verify(jwtAuthentication.getEncodedJWT());
            } catch (SignatureVerificationException | AlgorithmMismatchException e) {
                throw new BadCredentialsException("JWT is signature is invalid", e);
            } catch (TokenExpiredException e) {
                throw new CredentialsExpiredException("JWT is expired", e);
            } catch (InvalidClaimException e) {
                throw new BadCredentialsException("JWT claims are invalid", e);
            }
        }

        jwtAuthentication.setAuthenticated(true);

        return jwtAuthentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }
}
