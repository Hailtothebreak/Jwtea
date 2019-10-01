package xyz.hailtothebreak.jwtea.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import xyz.hailtothebreak.jwtea.configuration.properties.JwtProperties;
import xyz.hailtothebreak.jwtea.context.parsing.AuthorizationHeaderTokenExtractor;
import xyz.hailtothebreak.jwtea.context.parsing.ScopeClaimAuthoritiesInterpreter;
import xyz.hailtothebreak.jwtea.context.parsing.TokenAuthoritiesInterpreter;
import xyz.hailtothebreak.jwtea.context.parsing.TokenExtractor;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtAutoConfiguration {

    private final JwtProperties properties;

    @Bean
    public JwtConfiguration jwtConfiguration() {
        return JwtConfiguration.from(properties);
    }

    @Bean
    @ConditionalOnMissingBean(TokenExtractor.class)
    public TokenExtractor authorizationHeaderTokenExtractor() {
        return new AuthorizationHeaderTokenExtractor();
    }

    @Bean
    @ConditionalOnMissingBean(TokenAuthoritiesInterpreter.class)
    public TokenAuthoritiesInterpreter scopeClaimAuthoritiesInterpreter() {
        return new ScopeClaimAuthoritiesInterpreter();
    }

    public JwtAutoConfiguration(JwtProperties properties) {
        this.properties = properties;
    }
}
