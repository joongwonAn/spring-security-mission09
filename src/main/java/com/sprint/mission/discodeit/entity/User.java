package com.sprint.mission.discodeit.entity;

import com.sprint.mission.discodeit.entity.base.BaseUpdatableEntity;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)  // JPA 를 위한 기본 생성자
public class User extends BaseUpdatableEntity {

    @Column(length = 50, nullable = false, unique = true)
    private String username;
    @Column(length = 100, nullable = false, unique = true)
    private String email;
    @Column(length = 60, nullable = false)
    private String password;
    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @JoinColumn(name = "profile_id", columnDefinition = "uuid")
    private BinaryContent profile;
    @Enumerated(EnumType.STRING)
    @Column(length = 20, nullable = false)
    private Role role;

    public User(String username, String email, String password, BinaryContent profile, Role role) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.profile = profile;
        this.role = role;
    }

    public void update(String newUsername, String newEmail, String newPassword,
                       BinaryContent newProfile) {
        if (newUsername != null && !newUsername.equals(this.username)) {
            this.username = newUsername;
        }
        if (newEmail != null && !newEmail.equals(this.email)) {
            this.email = newEmail;
        }
        if (newPassword != null && !newPassword.equals(this.password)) {
            this.password = newPassword;
        }
        if (newProfile != null) {
            this.profile = newProfile;
        }
    }

    public void updateRole(Role newRole) {
        if (newRole != null) {
            this.role = newRole;
        }
    }
}
