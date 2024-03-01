package com.signaturegenerator.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class SymmetricSignatureRequestDto {
    private String clientSecret;
    private String httpMethod;
    private String relativePath;
    private String accessToken;
    private String requestBody;
    private String timestamp;
}
