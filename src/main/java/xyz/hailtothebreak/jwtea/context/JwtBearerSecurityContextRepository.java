package xyz.hailtothebreak.jwtea.context;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import xyz.hailtothebreak.jwtea.context.parsing.TokenAuthoritiesInterpreter;
import xyz.hailtothebreak.jwtea.context.parsing.TokenExtractor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Objects;

public class JwtBearerSecurityContextRepository implements SecurityContextRepository {

    private final TokenExtractor tokenExtractor;
    private final TokenAuthoritiesInterpreter tokenAuthoritiesInterpreter;

    public JwtBearerSecurityContextRepository(TokenExtractor tokenExtractor,
                                              TokenAuthoritiesInterpreter tokenAuthoritiesInterpreter) {
        this.tokenExtractor = tokenExtractor;
        this.tokenAuthoritiesInterpreter = tokenAuthoritiesInterpreter;
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder httpRequestResponseHolder) {
        final SecurityContext context = SecurityContextHolder.createEmptyContext();

        final String token = tokenExtractor.extractFromRequest(httpRequestResponseHolder.getRequest());

        if(Objects.isNull(token)) {
            return context;
        }

        try {
            final DecodedJWT decodedJWT = JWT.decode(token);

            final List<GrantedAuthority> grantedAuthorities
                    = tokenAuthoritiesInterpreter.interpretGrantedAuthorities(decodedJWT);

            context.setAuthentication(new JwtAuthentication(decodedJWT, grantedAuthorities));
        } catch (JWTDecodeException e) {
            // leave context without an authentication
        }

        return context;
    }

    @Override
    public void saveContext(SecurityContext securityContext,
                            HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse) {
        // Unused because of stateless nature of JWTs
    }

    @Override
    public boolean containsContext(HttpServletRequest httpServletRequest) {
        return !Objects.isNull(tokenExtractor.extractFromRequest(httpServletRequest));
    }
}
