package com.trendchat.trendchatcommon.auth;

import com.trendchat.trendchatcommon.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * JWT 토큰에서 추출한 사용자 인증 정보를 담는 클래스입니다.
 * <p>
 * 인증 필터에서 JWT 검증 후 {@link org.springframework.security.core.Authentication}
 * 객체로 변환될 때, 사용자 정보의 페이로드로 활용됩니다.
 * </p>
 *
 * <p>
 * Spring Security에서 인증된 사용자의 principal 정보로 사용되며,
 * 권한 및 사용자 식별 정보를 포함합니다.
 * </p>
 */
@Getter
@AllArgsConstructor
public class AuthUser {

    /** 사용자 고유 식별자 (예: UUID 또는 DB ID) */
    private String userId;

    /** 사용자 닉네임 */
    private String nickname;

    /** 사용자 권한 (예: ROLE_FREE, ROLE_PREMIUM, ROLE_ADMIN) */
    private UserRole userRole;

    /** 계정 잠김 여부 (true일 경우 잠기지 않음) */
    private boolean accountNonLocked;
}