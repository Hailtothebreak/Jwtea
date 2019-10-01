package xyz.hailtothebreak.jwtea.configuration.properties;

import lombok.Data;

@Data
public class JwtAlgorithmProperties {
    private boolean noneEnabled = false;

    private JwtHMACProperties HMAC256;
    private JwtHMACProperties HMAC384;
    private JwtHMACProperties HMAC512;
}
