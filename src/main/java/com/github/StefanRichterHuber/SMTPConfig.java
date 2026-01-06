package com.github.StefanRichterHuber;

import java.io.File;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "smtp")
public interface SMTPConfig {
    String host();

    String port();

    String senderEmail();

    String senderPassword();

    File senderSecretKeyFile();

    String senderSecretKeyPassword();

    File recipientPublicKeyFile();
}
