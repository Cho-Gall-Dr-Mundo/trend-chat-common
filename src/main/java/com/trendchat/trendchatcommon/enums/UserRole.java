package com.trendchat.trendchatcommon.enums;

import java.util.Arrays;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * 사용자 권한을 나타내는 열거형입니다.
 * <p>
 * 각 역할은 Spring Security에서 사용되는 권한 문자열(ROLE_ 접두사 포함)을 포함합니다.
 * 역할 이름은 JWT 내 클레임 혹은 DB 저장값과 매칭되며,
 * {@link #of(String)} 메서드를 통해 문자열에서 enum으로 변환할 수 있습니다.
 * </p>
 */
@Getter
@RequiredArgsConstructor
public enum UserRole {
    ROLE_ADMIN(Authority.ADMIN),
    ROLE_FREE(Authority.FREE),
    ROLE_PREMIUM(Authority.PREMIUM);

    private final String authority;

    /**
     * 주어진 문자열로부터 {@link UserRole}을 찾습니다.
     *
     * @param role 대소문자 구분 없이 enum name 과 일치하는 문자열
     * @return 매칭되는 {@link UserRole} 인스턴스
     * @throws IllegalArgumentException 유효하지 않은 역할 문자열일 경우
     */
    public static UserRole of(String role) {
        return Arrays.stream(UserRole.values())
                .filter(r -> r.name().equalsIgnoreCase(role))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid UserRole:" + role));
    }

    /**
     * 각 사용자 역할에 해당하는 권한 상수를 정의하는 내부 static 클래스입니다.
     * <p>
     * 이 값들은 주로 {@code SimpleGrantedAuthority} 등에서 사용됩니다.
     * </p>
     */
    public static class Authority {
        public static final String ADMIN = "ROLE_ADMIN";
        public static final String FREE = "ROLE_FREE";
        public static final String PREMIUM = "ROLE_PREMIUM";
    }
}