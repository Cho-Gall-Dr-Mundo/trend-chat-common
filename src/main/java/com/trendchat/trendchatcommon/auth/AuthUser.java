package com.trendchat.trendchatcommon.auth;

import com.trendchat.trendchatcommon.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AuthUser {

    private String userId;
    private String nickname;
    private UserRole userRole;
    private boolean accountNonLocked;
}