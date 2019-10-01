package xyz.hailtothebreak.jwtea.context.parsing;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class ScopeClaimAuthoritiesInterpreter implements TokenAuthoritiesInterpreter {
    @Override
    public List<GrantedAuthority> interpretGrantedAuthorities(DecodedJWT decodedJWT) {
        final String[] scopeClaimValue = decodedJWT.getClaim("scope").asArray(String.class);

        if(Objects.isNull(scopeClaimValue) || scopeClaimValue.length == 0) {
            return Collections.emptyList();
        }

        final ArrayList<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        for (String scope : scopeClaimValue) {
            grantedAuthorities.add(new SimpleGrantedAuthority(scope));
        }

        return grantedAuthorities;
    }
}
