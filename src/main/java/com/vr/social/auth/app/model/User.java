package com.vr.social.auth.app.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "users") // Avoids conflict with reserved SQL keyword "user"
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String provider; // 'google' or 'facebook', etc.

    private String pictureUrl; // Optional field for Google/Facebook profile picture
}
