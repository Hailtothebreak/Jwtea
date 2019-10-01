package xyz.hailtothebreak.jwtea.context;

import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@RequiredArgsConstructor
public class JwtAuthentication implements Authentication {

    @Getter
    private final DecodedJWT decodedJWT;

    @Getter // Overrides getAuthenticated
    @Setter // Overrides setAuthenticated
    private boolean authenticated = false;

    @Getter // Overrides getAuthorities
    private final List<GrantedAuthority> authorities;

    public String getAlgorithmName() {
        return decodedJWT.getAlgorithm();
    }

    public String getKeyId() {
        return decodedJWT.getKeyId();
    }

    public String getEncodedJWT() {
        return decodedJWT.getToken();
    }

    public String getCourriel() { return decodedJWT.getClaim("courriel").asString(); }

    @Override
    public Object getCredentials() {
        return decodedJWT.getToken();
    }

    @Override
    public Object getDetails() {
        return decodedJWT;
    }

    @Override
    public Object getPrincipal() {
        return decodedJWT.getSubject();
    }

    @Override
    public String getName() {
        return decodedJWT.getSubject();
    }
}
