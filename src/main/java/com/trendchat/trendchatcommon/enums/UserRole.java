package com.trendchat.trendchatcommon.enums;

import java.util.Arrays;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum UserRole {
    ROLE_ADMIN(Authority.ADMIN),
    ROLE_FREE(Authority.FREE),
    ROLE_PREMIUM(Authority.PREMIUM);

    private final String authority;

    public static UserRole of(String role) {
        return Arrays.stream(UserRole.values())
                .filter(r -> r.name().equalsIgnoreCase(role))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid UserRole:" + role));
    }

    public static class Authority {

        public static final String ADMIN = "ROLE_ADMIN";
        public static final String FREE = "ROLE_FREE";
        public static final String PREMIUM = "ROLE_PREMIUM";
    }
}