package com.signaturegenerator.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.signaturegenerator.dto.SignatureResponseDto;
import com.signaturegenerator.dto.SymmetricSignatureRequestDto;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Service
@AllArgsConstructor
public class SymmetricSignatureService {

    private static String clientSecret = "bnHMDkUO3OQW4akhAwEKyHoxkronC3ir";

    public SignatureResponseDto generate(SymmetricSignatureRequestDto requestDto) throws JsonProcessingException, NoSuchAlgorithmException, InvalidKeyException {
//        <HTTP METHOD> + ”:” + <RELATIVE PATH URL> + “:“ + <TOKEN> + “:“ + LowerCase(HexEncode(SHA-256(Minify(<HTTP BODY>)))) + “:“ + <X-TIMESTAMP>
        String minifyBody = minifyBody(requestDto.getRequestBody());
        String hexEncodedMinifyBody = sha256Hex(minifyBody);
        String stringToSign = String.join(":",
                requestDto.getHttpMethod(),
                requestDto.getRelativePath(),
                requestDto.getAccessToken(),
                hexEncodedMinifyBody,
                requestDto.getTimestamp());
        String signature = generateSignature(clientSecret, stringToSign);

        return SignatureResponseDto.builder()
                .stringToSign(stringToSign)
                .signature(signature)
                .build();
    }

    private static String minifyBody(String input) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        Object jsonObject = mapper.readValue(input, Object.class);
        return mapper.writeValueAsString(jsonObject);
    }

    private static String sha256Hex(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String generateSignature(String secret, String input) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
        Mac hmac = Mac.getInstance("HmacSHA512");
        hmac.init(secretKey);
        byte[] to = hmac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(to);
    }
}
