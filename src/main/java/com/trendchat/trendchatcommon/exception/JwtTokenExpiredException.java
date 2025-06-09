package com.trendchat.trendchatcommon.exception;

/**
 * JWT 토큰이 만료되었을 때 발생하는 사용자 정의 예외입니다.
 * <p>
 * Spring Security 또는 인증 필터에서 만료된 토큰을 감지하면 이 예외가 발생합니다.
 * 이 예외는 주로 401 Unauthorized 응답을 생성하여 토큰을 갱신하는데 사용됩니다.
 * </p>
 */
public class JwtTokenExpiredException extends RuntimeException {

    /**
     * 지정된 메시지와 원인으로 새로운 JwtTokenExpiredException을 생성합니다.
     *
     * @param message 예외에 대한 설명 메시지
     * @param cause   원래 발생한 예외 (예: TokenExpiredException from auth0)
     */
    public JwtTokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}