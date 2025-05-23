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

@Slf4j
public class JwtUtil {

    private final String AUTHORIZATION_HEADER = "Authorization";
    private final String REFRESH_TOKEN_HEADER = "refreshToken";
    private final String BEARER_PREFIX = "Bearer ";

    private final String accessSecretKey;
    private final String refreshSecretKey;

    public JwtUtil(String accessSecretKey, String refreshSecretKey){
        this.accessSecretKey = accessSecretKey;
        this.refreshSecretKey = refreshSecretKey;
    }

    public String createAccessToken(String userId, String nickname, String role) {
        return BEARER_PREFIX + JWT.create()
                .withSubject(userId)
                .withExpiresAt(new Date(System.currentTimeMillis() + 60 * 30 * 1000L))
                .withClaim("nickname", nickname)
                .withClaim("role", role)
                .sign(Algorithm.HMAC512(accessSecretKey));
    }

    public String createRefreshToken(String userId) {
        return BEARER_PREFIX + JWT.create()
                .withSubject(userId)
                .withExpiresAt(new Date(System.currentTimeMillis() + 60 * 60 * 24 * 14 * 1000L))
                .sign(Algorithm.HMAC512(refreshSecretKey));
    }

    public void addAccessTokenToHeader(HttpServletResponse response, String accessToken) {
        response.addHeader(AUTHORIZATION_HEADER, accessToken);
    }

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

    public String getAccessTokenFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (bearerToken != null && !bearerToken.trim().isEmpty() && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }

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

    public DecodedJWT getUserInfoFromToken(String token) {
        token = token.replace(BEARER_PREFIX, "");

        try {
            return JWT.decode(token);
        } catch (Exception e) {
            throw new InvalidTokenException("Token parsing failed");
        }
    }

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