package com.trendchat.trendchatcommon.exception;

/**
 * JWT 토큰이 유효하지 않을 때 발생하는 사용자 정의 예외입니다.
 * <p>
 * JWT 서명 검증 실패, 형식 오류, 알고리즘 불일치 등의 경우에 사용됩니다.
 * 이 예외는 주로 인증 과정에서 클라이언트의 토큰이 신뢰할 수 없는 경우 발생하며,
 * 일반적으로 HTTP 401 Unauthorized 응답을 트리거하는 데 사용됩니다.
 * </p>
 */
public class InvalidTokenException extends RuntimeException {

    /**
     * 주어진 메시지를 포함한 InvalidTokenException을 생성합니다.
     *
     * @param message 예외 메시지. 유효하지 않은 이유를 설명합니다.
     */
    public InvalidTokenException(String message) {
        super(message);
    }
}