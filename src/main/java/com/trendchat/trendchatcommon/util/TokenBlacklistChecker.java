package com.trendchat.trendchatcommon.util;

/**
 * 액세스 토큰의 블랙리스트 여부를 확인하는 인터페이스입니다.
 * <p>
 * 구현체는 주어진 액세스 토큰이 블랙리스트에 등록되어 있는지 여부를 판단하는
 * 로직을 제공해야 합니다.
 * </p>
 * <p>
 * 이 인터페이스를 통해 블랙리스트 저장소(예: Redis, 데이터베이스)에 대한 의존성을 추상화할 수 있습니다.
 * </p>
 */
public interface TokenBlacklistChecker {

    /**
     * 주어진 액세스 토큰이 블랙리스트에 포함되어 있는지 확인합니다.
     *
     * @param accessToken 검사할 액세스 토큰 문자열 (Bearer 접두사 제외)
     * @return 블랙리스트에 포함되어 있으면 {@code true}, 그렇지 않으면 {@code false}
     */
    boolean isBlacklisted(String accessToken);
}