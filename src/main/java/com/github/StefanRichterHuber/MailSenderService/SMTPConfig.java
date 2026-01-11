package com.github.StefanRichterHuber.MailSenderService;

import java.io.File;
import java.util.List;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "smtp")
public interface SMTPConfig {
    /**
     * The SMTP host to connect to.
     */
    String host();

    /**
     * The SMTP port to connect to.
     */
    String port();

    /**
     * The sender address to use.
     */
    String from();

    /**
     * The SMTP username to use.
     */
    String user();

    /**
     * The SMTP password to use.
     */
    String password();

    /**
     * The sender's secrect key file. Should contain both the private key and the
     * public key (armored ascii format).
     */
    File senderSecretKeyFile();

    /**
     * The sender's secrect key password.
     */
    String senderSecretKeyPassword();

    /**
     * List of VKS key servers to use for key lookup.
     * 
     * @return
     */
    @WithDefault("https://keys.openpgp.org")
    List<String> vksKeyServers();

    /**
     * List of Mailvelope key servers to use for key lookup.
     * 
     * @return
     */
    @WithDefault("https://keys.mailvelope.com")
    List<String> mailvelopeKeyServers();

    /**
     * Whether to use Inline PGP. This mode is compatible with Mailvelope.
     * Attachmemts, however, are added as detached encrypted files and need to be
     * decrypted separately from the main message. Moreover, headers are not
     * protected.
     */
    @WithDefault("true")
    boolean inlinePGP();

    /**
     * Whether to add an Autocrypt header to the email.
     */
    @WithDefault("true")
    boolean autocrypt();

    /**
     * Protects (encrypts) the headers (espec. subject) of the email. Not compatible
     * with Inline PGP. Not compatible with K9.
     */
    @WithDefault("true")
    boolean protectHeaders();

    /**
     * The placeholder for the subject of the email if headers are protected. See
     * specification for details.
     */
    @WithDefault("...")
    String encryptedSubjectPlaceholder();

    /**
     * Whether to fallback to plain mail if not all recipients have a certificate.
     */
    @WithDefault("false")
    boolean fallbackToPlainMail();

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
