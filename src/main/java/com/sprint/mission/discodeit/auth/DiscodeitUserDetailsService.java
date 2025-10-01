package com.sprint.mission.discodeit.auth;

import com.sprint.mission.discodeit.dto.data.UserDto;
import com.sprint.mission.discodeit.entity.User;
import com.sprint.mission.discodeit.entity.UserStatus;
import com.sprint.mission.discodeit.exception.user.UserNotFoundException;
import com.sprint.mission.discodeit.exception.userstatus.UserStatusNotFoundException;
import com.sprint.mission.discodeit.mapper.UserMapper;
import com.sprint.mission.discodeit.repository.UserRepository;
import com.sprint.mission.discodeit.repository.UserStatusRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/*
 * UserDetailsService 컴포넌트 대체
 *
 * UserDetailsService: username을 기반으로 사용자 세부 정보(UserDetails)를 DB 등에서 불러오는 역할
 */

@Service
@RequiredArgsConstructor
public class DiscodeitUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final UserStatusRepository userStatusRepository;

    private final UserMapper userMapper;

    @Override
    public DiscodeitUserDetails loadUserByUsername(String username) throws UsernameNotFoundException { // 특정 사용자 정보 가져오기
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> UserNotFoundException.withUsername(username));

        Boolean isOnline = userStatusRepository.findByUserId(user.getId())
                .map(UserStatus::isOnline)
                .orElseThrow(() -> UserStatusNotFoundException.withUserId(user.getId()));

        UserDto userDto = new UserDto(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                userMapper.toDto(user).profile(),
                isOnline,
                user.getRole()
        );

        return new DiscodeitUserDetails(userDto, user.getPassword());
    }
}
