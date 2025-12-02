package com.finalyear.event.controller;

import com.finalyear.event.payload.request.RegisterUserRequest;
import com.finalyear.event.payload.request.UserUpdateRequest;
import com.finalyear.event.payload.request.OtpRequest;
import com.finalyear.event.payload.request.VerifyOtpRequest;
import com.finalyear.event.security.JwtTokenProvider;
import com.finalyear.event.service.OtpService;
import com.finalyear.event.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final OtpService otpService;
    private final JwtTokenProvider jwtTokenProvider;

    public UserController(UserService userService,
                          OtpService otpService,
                          JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.otpService = otpService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    // -------------------- REGISTER USER --------------------
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterUserRequest request) {
        return ResponseEntity.ok(userService.register(request));
    }

    // -------------------- SEND OTP --------------------
    @PostMapping("/otp")
    public ResponseEntity<?> sendOtp(@RequestBody OtpRequest request) {
        otpService.generateAndSendOtp(request.getEmail());
        return ResponseEntity.ok(
                new MessageResponse("OTP sent to email successfully")
        );
    }

    // -------------------- VERIFY OTP + GENERATE TOKEN --------------------
    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody VerifyOtpRequest req) {

        boolean ok = userService.verifyOtp(req.getEmail(), req.getOtp());

        if (!ok) {
            return ResponseEntity.status(400)
                    .body(new MessageResponse("Invalid OTP"));
        }

        String token = jwtTokenProvider.generateToken(req.getEmail(), "STUDENT");

        return ResponseEntity.ok(new TokenResponse(token));
    }

    // -------------------- UPDATE USER --------------------
    @PutMapping("/{userId}")
    public ResponseEntity<?> update(
            @PathVariable String userId,
            @RequestBody UserUpdateRequest request) {

        return ResponseEntity.ok(userService.update(userId, request));
    }

    // ----------- RESPONSE CLASSES -----------

    private record TokenResponse(String token) {}

    private record MessageResponse(String message) {}
}
