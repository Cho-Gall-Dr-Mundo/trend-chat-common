package com.trendchat.trendchatcommon.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.trendchat.trendchatcommon.auth.AuthUser;
import com.trendchat.trendchatcommon.enums.UserRole;
import com.trendchat.trendchatcommon.exception.InvalidTokenException;
import com.trendchat.trendchatcommon.exception.JwtTokenExpiredException;
import com.trendchat.trendchatcommon.util.JwtUtil;
import com.trendchat.trendchatcommon.util.TokenBlacklistChecker;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * WebFlux 기반의 JWT 인증 필터입니다.
 * <p>
 * 요청의 Authorization 헤더에서 Bearer 토큰을 추출하고,
 * 유효한 토큰인 경우 인증 객체를 생성하여 {@link ReactiveSecurityContextHolder}에 등록합니다.
 * 인증이 필요 없는 경로(예: /api/v1/auth/**)는 필터를 통과시킵니다.
 * </p>
 *
 * @author Doolchong
 */
@Slf4j(topic = "JWT Verification and Authorization")
@RequiredArgsConstructor
public class AuthorizationFilterWebFlux implements WebFilter {

    private final JwtUtil jwtUtil;
    private final TokenBlacklistChecker blacklistChecker;

    /**
     * WebFlux 요청에 대한 JWT 인증 필터 처리 메서드입니다.
     * <p>
     * 다음과 같은 흐름으로 작동합니다:
     * <ol>
     *     <li>인증이 필요 없는 경로(`/api/v1/auth/**`)는 필터를 건너뜁니다.</li>
     *     <li>요청 헤더에서 Access Token을 추출합니다.</li>
     *     <li>토큰이 존재할 경우:
     *         <ul>
     *             <li>JWT 유효성 검사를 수행하고, 실패 시 401 응답 반환</li>
     *             <li>토큰이 블랙리스트에 포함된 경우 401 응답 반환</li>
     *             <li>정상 토큰이면 Authentication 객체를 생성하고 SecurityContext에 등록</li>
     *         </ul>
     *     </li>
     *     <li>필터 체인의 다음 WebFilter로 요청을 전달하며, SecurityContext를 함께 설정합니다.</li>
     * </ol>
     *
     * @param exchange 현재 HTTP 요청 및 응답을 포함하는 서버 웹 교환 객체
     * @param chain    필터 체인
     * @return 인증 성공 시 다음 필터로 전달하는 {@link Mono}, 인증 실패 시 401 응답으로 종료
     */
    @NonNull
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();

        if (path.startsWith("/api/v1/auth/")) {
            return chain.filter(exchange);
        }

        String tokenValue = jwtUtil.getAccessTokenFromHeader(exchange.getRequest());

        if (!StringUtils.hasText(tokenValue)) {
            return chain.filter(exchange);
        }

        try {
            DecodedJWT decoded = jwtUtil.validateToken(tokenValue);

            if (blacklistChecker.isBlacklisted(tokenValue)) {
                log.warn("Access token is blacklisted: {}", tokenValue);
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            Authentication authentication = createAuthentication(decoded);
            SecurityContext context = new SecurityContextImpl(authentication);

            return chain.filter(exchange)
                    .contextWrite(
                            ReactiveSecurityContextHolder.withSecurityContext(Mono.just(context)));

        } catch (JwtTokenExpiredException e) {
            log.error("Expired token: {}", e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();

        } catch (InvalidTokenException e) {
            log.error("Token verification failed: {}", e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    /**
     * JWT에서 인증 정보를 추출하여 Spring Security의 Authentication 객체를 생성합니다.
     *
     * @param info 디코딩된 JWT 정보
     * @return 인증된 사용자의 {@link Authentication} 객체
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
}