package xyz.hailtothebreak.jwtea.configuration;

import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.*;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import xyz.hailtothebreak.jwtea.context.JwtAuthenticationProvider;
import xyz.hailtothebreak.jwtea.context.JwtBearerSecurityContextRepository;
import xyz.hailtothebreak.jwtea.context.parsing.TokenAuthoritiesInterpreter;
import xyz.hailtothebreak.jwtea.context.parsing.TokenExtractor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtWebSecurityConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<JwtWebSecurityConfigurer<H>, H> {

    @Override
    @SuppressWarnings("unchecked")
    public void init(final H http) throws Exception {
        super.init(http);

        // Load configuration from holder bean
        final JwtConfigurationHolder configurerComponent = new JwtConfigurationHolder();
        postProcess(configurerComponent);
        final JwtConfiguration jwtAutoConfiguration = configurerComponent.getJwtConfiguration();
        final TokenExtractor tokenExtractor
                = configurerComponent.getTokenExtractor();
        final TokenAuthoritiesInterpreter tokenAuthoritiesInterpreter
                = configurerComponent.getTokenAuthoritiesInterpreter();

        // Setup jwt auth config
        http.authenticationProvider(new JwtAuthenticationProvider(jwtAutoConfiguration));
        http.getConfigurer(SecurityContextConfigurer.class)
                .securityContextRepository(new JwtBearerSecurityContextRepository(
                        tokenExtractor, tokenAuthoritiesInterpreter));
        http.getConfigurer(ExceptionHandlingConfigurer.class)
                .authenticationEntryPoint(
                        JwtWebSecurityConfigurer::authenticationEntryPoint);

        // Disable defaults not needed for jwt
        http.removeConfigurer(HttpBasicConfigurer.class);
        http.removeConfigurer(CsrfConfigurer.class);
        http.getConfigurer(SessionManagementConfigurer.class)
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    private static void authenticationEntryPoint(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }

    @Data
    @Component
    private static class JwtConfigurationHolder {
        @Autowired
        private JwtConfiguration jwtConfiguration;

        @Autowired
        private TokenExtractor tokenExtractor;

        @Autowired
        private TokenAuthoritiesInterpreter tokenAuthoritiesInterpreter;
    }
}
