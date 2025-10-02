package com.sprint.mission.discodeit.config;

import com.sprint.mission.discodeit.entity.Role;
import com.sprint.mission.discodeit.entity.User;
import com.sprint.mission.discodeit.entity.UserStatus;
import com.sprint.mission.discodeit.repository.UserRepository;
import com.sprint.mission.discodeit.repository.UserStatusRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class AdminInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final UserStatusRepository userStatusRepository;

    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        boolean exists = userRepository.existsByRole(Role.ADMIN);
        if (!exists) {
            User admin = new User(
                    "admin",
                    "admin@gmail.com"
                    , passwordEncoder.encode("admin1!"),
                    null,
                    Role.ADMIN
            );
            UserStatus adminStatus = new UserStatus(
                    admin,
                    Instant.now()
            );
            userRepository.save(admin);
            userStatusRepository.save(adminStatus);

            log.debug("Created Admin obj");
        } else {
            log.debug("Admin already exists");
        }

    }
}
