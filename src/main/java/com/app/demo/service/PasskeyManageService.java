package com.app.demo.service;

import com.app.demo.dto.response.PasskeyResponseDto;

import java.util.List;

public interface PasskeyManageService {

    List<PasskeyResponseDto> findPasskeysByUsername(String username);

    void deletePasskeyForUser(String username, String credentialIdBase64Url);
}
