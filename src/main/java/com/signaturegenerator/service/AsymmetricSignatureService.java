package com.signaturegenerator.service;

import com.signaturegenerator.dto.AsymmetricSignatureRequestDto;
import com.signaturegenerator.dto.SignatureResponseDto;
import org.apache.coyote.BadRequestException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

@Service
public class AsymmetricSignatureService {

    public SignatureResponseDto generate(AsymmetricSignatureRequestDto requestDto) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, BadRequestException {
//        ZoneId zoneId = ZoneId.of("Asia/Jakarta");
//        String timestamp = DateTimeFormatter.ofPattern(requestDto.getTimestamp()).format(ZonedDateTime.of(LocalDateTime.now(), zoneId));
        String input = String.join("|", requestDto.getClientId(), requestDto.getTimestamp());
        String signature = sign(input, requestDto.getPrivateKey());
        boolean verify = verify(input, signature, requestDto.getPublicKey());
        if (verify) {
            return SignatureResponseDto.builder()
                    .stringToSign(input)
                    .signature(signature)
                    .build();
        } {
            throw new BadRequestException("Signature not verified");
        }
    }

    private static String sign(String input, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        String realPK = clearPrivateKey(privateKey);
        byte[] privateKeyBytes = Base64.getDecoder().decode(realPK);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pk = kf.generatePrivate(spec);
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(pk);
        sign.update(input.getBytes(StandardCharsets.UTF_8));
        byte[] s = sign.sign();
        return Base64.getEncoder().encodeToString(s);
    }

    private static boolean verify(String input, String signature, String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        String realPK = clearPublicKey(publicKey);
        byte[] publicKeyBytes = Base64.getDecoder().decode(realPK);
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pk = keyFactory.generatePublic(publicKeySpec);
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(pk);
        sign.update(input.getBytes(StandardCharsets.UTF_8));
        byte[] s = Base64.getDecoder().decode(signature);
        return sign.verify(s);
    }

    private static String clearPrivateKey(String pKey) {
        return pKey.replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("\n", "");
    }

    private static String clearPublicKey(String pKey) {
        return pKey.replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("\n", "");
    }
}
