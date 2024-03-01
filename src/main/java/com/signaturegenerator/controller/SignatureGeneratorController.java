package com.signaturegenerator.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.signaturegenerator.dto.AsymmetricSignatureRequestDto;
import com.signaturegenerator.dto.SignatureResponseDto;
import com.signaturegenerator.dto.SymmetricSignatureRequestDto;
import com.signaturegenerator.service.AsymmetricSignatureService;
import com.signaturegenerator.service.SymmetricSignatureService;
import lombok.AllArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

@RestController
@RequestMapping("")
@AllArgsConstructor
public class SignatureGeneratorController {

    private AsymmetricSignatureService asymmetricSignatureService;
    private SymmetricSignatureService symmetricSignatureService;

    @PostMapping("/asymmetric-signature")
    public ResponseEntity<SignatureResponseDto> generateAsymmetric(
            @RequestBody AsymmetricSignatureRequestDto requestDto)
            throws BadRequestException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        return ResponseEntity.ok(asymmetricSignatureService.generate(requestDto));
    }

    @PostMapping("/symmetric-signature")
    public ResponseEntity<SignatureResponseDto> generateSymmetric(
            @RequestHeader(name = "x-request-body") String xRequestBody,
            @RequestHeader(name = "x-http-method") String xHttpMethod,
            @RequestHeader(name = "x-relative-path") String xRelativePath,
            @RequestBody SymmetricSignatureRequestDto requestDto)
            throws NoSuchAlgorithmException, InvalidKeyException, JsonProcessingException {
        requestDto.setRequestBody(xRequestBody);
        requestDto.setHttpMethod(xHttpMethod);
        requestDto.setRelativePath(xRelativePath);
        return ResponseEntity.ok(symmetricSignatureService.generate(requestDto));
    }
}
