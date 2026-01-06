package com.github.StefanRichterHuber;

import java.io.File;
import java.util.Map;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "smtp")
public interface SMTPConfig {
    String host();

    String port();

    String from();

    String user();

    String password();

    File senderSecretKeyFile();

    String senderSecretKeyPassword();

    File recipientPublicKeyFile();

    /**
     * Protects (encrypts) the headers (espec. subject) of the email.
     */
    @WithDefault("true")
    boolean protectHeaders();

    /**
     * The placeholder for the subject of the email if headers are protected. See
     * specification for details.
     */
    @WithDefault("...")
    String encryptedSubjectPlaceholder();

    @WithDefault("false")
    boolean tls();

    @WithDefault("false")
    boolean startTlsEnabled();

    @WithDefault("false")
    boolean login();

    @WithDefault("false")
    boolean sslEnabled();

    @WithDefault("false")
    boolean authEnabled();

    @WithDefault("${smtp.host}")
    String sslTrust();
}
