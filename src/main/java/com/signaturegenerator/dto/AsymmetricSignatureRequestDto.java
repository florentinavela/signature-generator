package com.signaturegenerator.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AsymmetricSignatureRequestDto {
    private String publicKey;
    private String privateKey;
    private String clientId;
    private String timestamp;
}
