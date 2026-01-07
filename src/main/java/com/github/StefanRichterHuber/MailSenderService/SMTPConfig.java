package com.github.StefanRichterHuber.MailSenderService;

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
     * Whether to use Inline PGP. This mode is compatible with Mailvelope.
     * Attachmemts, however, are added as detached encrypted files and need to be
     * decrypted separately from the main message.
     */
    @WithDefault("true")
    boolean inlinePGP();

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
