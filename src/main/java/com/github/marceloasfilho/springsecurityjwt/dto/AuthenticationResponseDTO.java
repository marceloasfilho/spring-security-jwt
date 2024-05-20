package com.github.marceloasfilho.springsecurityjwt.dto;

import lombok.Builder;

@Builder
public record AuthenticationResponseDTO(String token) {
}
