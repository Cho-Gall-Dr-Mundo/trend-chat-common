package com.trendchat.trendchatcommon.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.trendchat.trendchatcommon.auth.AuthUser;
import com.trendchat.trendchatcommon.enums.UserRole;
import com.trendchat.trendchatcommon.exception.InvalidTokenException;
import com.trendchat.trendchatcommon.exception.JwtTokenExpiredException;
import com.trendchat.trendchatcommon.util.BlacklistChecker;
import com.trendchat.trendchatcommon.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.token.TokenService;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * MVC 기반(Spring Servlet 환경)의 JWT 인증 필터입니다.
 * <p>
 * 요청의 Authorization 헤더에서 Bearer 토큰을 추출하고,
 * 유효한 JWT인 경우 인증 객체를 생성하여 {@link SecurityContextHolder}에 등록합니다.
 * </p>
 * <p>
 * 인증이 필요 없는 경로(예: /api/v1/auth/**)는 필터를 건너뜁니다.
 * </p>
 *
 * @author Doolchong
 */
@Slf4j(topic = "JWT Verification and Authorization")
@RequiredArgsConstructor
public class AuthorizationFilterMvc extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final BlacklistChecker blacklistChecker;

    /**
     * 각 HTTP 요청마다 실행되는 JWT 인증 처리 메서드입니다.
     * <p>
     * 다음과 같은 흐름으로 동작합니다:
     * <ol>
     *     <li>인증이 필요 없는 경로(`/api/v1/auth/**`)는 필터를 통과시킵니다.</li>
     *     <li>요청 헤더에서 Access Token을 추출합니다.</li>
     *     <li>토큰이 존재할 경우:
     *         <ul>
     *             <li>JWT 유효성 검사를 수행하고, 실패 시 401 응답 반환</li>
     *             <li>블랙리스트에 포함된 토큰이나 userId인지 확인하고, 포함된 경우 401 응답 반환</li>
     *             <li>정상이면 인증 객체를 생성하여 SecurityContext에 등록</li>
     *         </ul>
     *     </li>
     *     <li>필터 체인의 다음 필터로 요청을 전달합니다.</li>
     * </ol>
     *
     * @param request     HTTP 요청 객체
     * @param response    HTTP 응답 객체
     * @param filterChain 필터 체인
     * @throws IOException      입출력 예외
     * @throws ServletException 서블릿 예외
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws IOException, ServletException {
        if (request.getRequestURI().startsWith("/api/v1/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String tokenValue = jwtUtil.getAccessTokenFromHeader(request);

        if (StringUtils.hasText(tokenValue)) {
            try {
                DecodedJWT info = jwtUtil.validateToken(tokenValue);
                String userId = info.getSubject();

                if (blacklistChecker.isBlacklisted(userId, tokenValue)) {
                    log.warn("Access token is blacklisted: {}", tokenValue);
                    handleUnauthorizedResponse(response, "Token is blacklisted");
                    return;
                }

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

    /**
     * JWT 정보를 기반으로 인증 객체를 SecurityContext에 등록합니다.
     *
     * @param info 디코딩된 JWT 정보
     */
    private void setAuthentication(DecodedJWT info) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        Authentication authentication = createAuthentication(info);
        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);
    }

    /**
     * JWT에서 사용자 정보를 추출하여 Spring Security {@link Authentication} 객체를 생성합니다.
     *
     * @param info 디코딩된 JWT
     * @return 인증 객체
     */
    private Authentication createAuthentication(DecodedJWT info) {
        AuthUser authUser = new AuthUser(
                info.getSubject(),
                info.getClaim("nickname").asString(),
                UserRole.of(info.getClaim("role").asString()),
                true
        );

        return new UsernamePasswordAuthenticationToken(
                authUser,
                null,
                List.of(new SimpleGrantedAuthority(authUser.getUserRole().getAuthority()))
        );
    }

    /**
     * 인증 실패(만료 또는 무효 토큰) 시 401 응답을 반환합니다.
     *
     * @param response   응답 객체
     * @param logMessage 로그에 기록할 메시지
     */
    private void handleUnauthorizedResponse(HttpServletResponse response, String logMessage) {
        log.error(logMessage);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}