package com.example.config;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * <h3>springboot-security</h3>
 * <p>自定义编码器</p>
 *
 * @author : 你的名字
 * @date : 2020-03-03 14:29
 **/
public class MyPasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence charSequence) {
        return charSequence.toString();
    }

    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return s.equals(charSequence.toString());
    }
}
