package com.trendchat.trendchatcommon.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.trendchat.trendchatcommon.exception.InvalidTokenException;
import com.trendchat.trendchatcommon.exception.JwtTokenExpiredException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;

/**
 * JWT(Access/Refresh Token)의 생성, 검증, 추출을 담당하는 유틸리티 클래스입니다.
 * <p>
 * Servlet 기반(HttpServletRequest/Response)과 WebFlux 기반(ServerHttpRequest) 모두 지원합니다.
 * </p>
 */
@Slf4j
public class JwtUtil {

    private final String AUTHORIZATION_HEADER = "Authorization";
    private final String REFRESH_TOKEN_HEADER = "refreshToken";
    private final String BEARER_PREFIX = "Bearer ";

    private final String accessSecretKey;
    private final String refreshSecretKey;

    /**
     * JwtUtil 생성자
     *
     * @param accessSecretKey  Access Token 암호화에 사용할 시크릿 키
     * @param refreshSecretKey Refresh Token 암호화에 사용할 시크릿 키
     */
    public JwtUtil(String accessSecretKey, String refreshSecretKey){
        this.accessSecretKey = accessSecretKey;
        this.refreshSecretKey = refreshSecretKey;
    }

    /**
     * Access Token 생성
     *
     * @param userId   사용자 ID (JWT subject)
     * @param nickname 사용자 닉네임 (claim)
     * @param role     사용자 역할 (claim)
     * @return 생성된 JWT 문자열 (Bearer prefix 포함)
     */
    public String createAccessToken(String userId, String nickname, String role) {
        return BEARER_PREFIX + JWT.create()
                .withSubject(userId)
                .withExpiresAt(new Date(System.currentTimeMillis() + 60 * 30 * 1000L))
                .withClaim("nickname", nickname)
                .withClaim("role", role)
                .sign(Algorithm.HMAC512(accessSecretKey));
    }

    /**
     * Refresh Token 생성
     *
     * @param userId 사용자 ID
     * @return 생성된 Refresh Token (Bearer prefix 포함)
     */
    public String createRefreshToken(String userId) {
        return BEARER_PREFIX + JWT.create()
                .withSubject(userId)
                .withExpiresAt(new Date(System.currentTimeMillis() + 60 * 60 * 24 * 14 * 1000L))
                .sign(Algorithm.HMAC512(refreshSecretKey));
    }

    /**
     * Access Token을 HTTP 헤더에 추가
     *
     * @param response    HTTP 응답 객체
     * @param accessToken Access Token 문자열
     */
    public void addAccessTokenToHeader(HttpServletResponse response, String accessToken) {
        response.addHeader(AUTHORIZATION_HEADER, accessToken);
    }

    /**
     * Refresh Token을 HTTP 쿠키에 추가 (Secure, HttpOnly, SameSite=None)
     *
     * @param response     HTTP 응답 객체
     * @param refreshToken Refresh Token 문자열
     */
    public void addRefreshTokenToCookie(HttpServletResponse response, String refreshToken) {
        refreshToken = URLEncoder.encode(refreshToken, StandardCharsets.UTF_8).replaceAll("\\+", "%20"); // Cookie Value 에는 공백이 불가능해서 encoding 진행
        Cookie cookie = new Cookie(REFRESH_TOKEN_HEADER, refreshToken);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(60 * 60 * 24 * 14);
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setAttribute("SameSite", "None");
        response.addCookie(cookie);
    }

    /**
     * Servlet 기반 요청에서 Access Token 추출
     *
     * @param request HTTP 요청 객체
     * @return JWT 문자열 (Bearer 제외) 또는 null
     */
    public String getAccessTokenFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (bearerToken != null && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    /**
     * WebFlux 기반 요청에서 Access Token 추출
     *
     * @param request WebFlux ServerHttpRequest 객체
     * @return JWT 문자열 (Bearer 제외) 또는 null
     */
    public String getAccessTokenFromHeader(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(AUTHORIZATION_HEADER);
        if (bearerToken != null && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    /**
     * Servlet 쿠키에서 Refresh Token 추출
     *
     * @param request HTTP 요청 객체
     * @return 디코딩된 Refresh Token 또는 null
     */
    public String resolveTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(REFRESH_TOKEN_HEADER)) {
                    // 쿠키 값 디코딩
                    return java.net.URLDecoder.decode(cookie.getValue(), StandardCharsets.UTF_8);
                }
            }
        }
        return null;
    }

    /**
     * JWT 토큰을 검증하고 디코딩된 정보를 반환
     *
     * @param token JWT 문자열 (Bearer 포함 가능)
     * @return 검증된 JWT 정보
     * @throws JwtTokenExpiredException 만료된 토큰
     * @throws InvalidTokenException    유효하지 않거나 파싱 불가능한 토큰
     */
    public DecodedJWT validateToken(String token) {
        token = token.replace(BEARER_PREFIX, "");

        try {
            return JWT
                    .require(Algorithm.HMAC512(accessSecretKey))
                    .build()
                    .verify(token);
        } catch (TokenExpiredException e) {
            throw new JwtTokenExpiredException("Expired JWT token", e);
        } catch (SignatureVerificationException e) {
            throw new InvalidTokenException("Invalid JWT signature");
        } catch (AlgorithmMismatchException e) {
            throw new InvalidTokenException("Unsupported JWT token");
        } catch (JWTDecodeException | IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid JWT claims");
        } catch (JWTVerificationException e) {
            throw new InvalidTokenException("JWT verification failed");
        }
    }

    /**
     * JWT에서 사용자 정보를 파싱하여 반환합니다.
     *
     * @param token JWT 문자열 (Bearer 포함 가능)
     * @return 디코딩된 JWT
     * @throws InvalidTokenException 파싱 실패 시
     */
    public DecodedJWT getUserInfoFromToken(String token) {
        token = token.replace(BEARER_PREFIX, "");

        try {
            return JWT.decode(token);
        } catch (Exception e) {
            throw new InvalidTokenException("Token parsing failed");
        }
    }

    /**
     * 모든 쿠키를 삭제합니다. (refreshToken 제거용)
     *
     * @param request  HTTP 요청 객체
     * @param response HTTP 응답 객체
     */
    public void clearAllCookies(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                cookie.setValue(null);
                cookie.setMaxAge(0);
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                response.addCookie(cookie);
            }
        }
    }
}