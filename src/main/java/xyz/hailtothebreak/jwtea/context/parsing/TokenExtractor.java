package xyz.hailtothebreak.jwtea.context.parsing;

import javax.servlet.http.HttpServletRequest;

@FunctionalInterface
public interface TokenExtractor {
    String extractFromRequest(HttpServletRequest request);
}
