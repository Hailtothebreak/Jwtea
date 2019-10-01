package xyz.hailtothebreak.jwtea.configuration.properties;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "spring.security.jwt")
public class JwtProperties {
    private boolean verificationEnabled = true;

    private String issuer;
    private String audience;
    private Long leeway;

    private JwtAlgorithmProperties algorithms;
}
