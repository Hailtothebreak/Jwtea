package xyz.hailtothebreak.jwtea.context.parsing;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

public interface TokenAuthoritiesInterpreter {
    List<GrantedAuthority> interpretGrantedAuthorities(DecodedJWT decodedJWT);
}
