package xyz.hailtothebreak.jwtea.context.parsing;

import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;

public class AuthorizationHeaderTokenExtractor implements TokenExtractor {

    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER = "bearer";

    @Override
    public String extractFromRequest(HttpServletRequest request) {
        final String authHeaderValue = request.getHeader(AUTHORIZATION);

        if(StringUtils.isBlank(authHeaderValue) || !authHeaderValue.toLowerCase().startsWith(BEARER)) {
            return null;
        }

        int startOfToken = authHeaderValue.indexOf(" ");

        if(startOfToken == -1) {
            return null;
        }

        return authHeaderValue.substring(startOfToken).trim();
    }
}
