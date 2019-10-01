package xyz.hailtothebreak.jwtea.configuration;

import com.auth0.jwt.algorithms.Algorithm;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import xyz.hailtothebreak.jwtea.configuration.properties.JwtAlgorithmProperties;
import xyz.hailtothebreak.jwtea.configuration.properties.JwtProperties;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Getter
@EqualsAndHashCode
@ToString
public class JwtConfiguration {

    private final boolean verificationEnabled;

    private final List<Algorithm> algorithms;
    private final String issuer;
    private final String audience;
    private final Long leeway;

    private JwtConfiguration(boolean verificationEnabled,
                             List<Algorithm> algorithms,
                             String issuer,
                             String audience,
                             Long leeway) {
        this.verificationEnabled = verificationEnabled;

        this.algorithms = algorithms;
        this.issuer = issuer;
        this.audience = audience;
        this.leeway = leeway;
    }

    private static List<Algorithm> parseAlgorithmProperties(JwtAlgorithmProperties properties) {
        List<Algorithm> algorithms = new ArrayList<>();

        if(Objects.isNull(properties)) {
           return algorithms;
        }

        if(properties.isNoneEnabled()) {
            algorithms.add(Algorithm.none());
        }

        if(!Objects.isNull(properties.getHMAC256())) {
            algorithms.add(Algorithm.HMAC256(properties.getHMAC256().getSecret().getBytes()));
        }

        if(!Objects.isNull(properties.getHMAC384())) {
            algorithms.add(Algorithm.HMAC384(properties.getHMAC256().getSecret().getBytes()));
        }

        if(!Objects.isNull(properties.getHMAC512())) {
            algorithms.add(Algorithm.HMAC512(properties.getHMAC256().getSecret().getBytes()));
        }

        return algorithms;
    }

    public static JwtConfiguration from(JwtProperties properties) {
        if(!properties.isVerificationEnabled()) {
            return new JwtConfiguration(
                    false,
                    Collections.emptyList(),
                    null,
                    null,
                    null
            );
        }

        return new JwtConfiguration(
                true,
                parseAlgorithmProperties(properties.getAlgorithms()),
                properties.getIssuer(),
                properties.getAudience(),
                properties.getLeeway()
        );
    }
}
