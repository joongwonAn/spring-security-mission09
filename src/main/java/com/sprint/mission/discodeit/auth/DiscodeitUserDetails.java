package com.sprint.mission.discodeit.auth;

import com.sprint.mission.discodeit.dto.data.BinaryContentDto;
import com.sprint.mission.discodeit.dto.data.UserDto;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/*
 * UserDetails 컴포넌트 대체
 *
 * UserDetails:
 * - 사용자 정보를 담는 객체
 * - 인증/권한 부여에 필요한 데이터 제공
 */

@Getter
@RequiredArgsConstructor
public class DiscodeitUserDetails implements UserDetails {
    private final UserDto userDto;
    private final String password;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(); // TODO: 엔티티에 role 필드 추가 후 변경 예정
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return userDto.username();
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }

    public String getEmail() {
        return userDto.email();
    }

    public BinaryContentDto getProfile() {
        return userDto.profile();
    }

    public Boolean isOnline() {
        return userDto.online();
    }
}
