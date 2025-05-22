package com.trendchat.trendchatcommon.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.trendchat.trendchatcommon.auth.AuthUser;
import com.trendchat.trendchatcommon.enums.UserRole;
import com.trendchat.trendchatcommon.exception.InvalidTokenException;
import com.trendchat.trendchatcommon.exception.JwtTokenExpiredException;
import com.trendchat.trendchatcommon.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j(topic = "JWT 검증 및 인가")
@RequiredArgsConstructor
public class AuthorizationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        if (request.getRequestURI().startsWith("/api/v1/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String tokenValue = jwtUtil.getAccessTokenFromHeader(request);

        if (StringUtils.hasText(tokenValue)) {
            try {
                DecodedJWT info = jwtUtil.validateToken(tokenValue);
                setAuthentication(info);
            } catch (JwtTokenExpiredException e) {
                handleUnauthorizedResponse(response, "Expired token: " + e.getMessage());
                return;
            } catch (InvalidTokenException e) {
                handleUnauthorizedResponse(response, "Token verification failed: " + e.getMessage());
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private void setAuthentication(DecodedJWT info) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        Authentication authentication = createAuthentication(info);
        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);
    }

    private Authentication createAuthentication(DecodedJWT info) {
        AuthUser authUser = new AuthUser(
                info.getSubject(),
                info.getClaim("nickname").asString(),
                UserRole.of(info.getClaim("role").asString()),
                true
        );

        return new UsernamePasswordAuthenticationToken(
                authUser, null,
                List.of(new SimpleGrantedAuthority(authUser.getUserRole().getAuthority()))
        );
    }

    private void handleUnauthorizedResponse(HttpServletResponse response, String logMessage) {
        log.error(logMessage);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}