package com.github.StefanRichterHuber.MailSenderService;

import java.util.Properties;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;

/**
 * Factory for creating a mail session.
 */
public class SessionFactory {

    /**
     * Configuration for the SMTP server.
     */
    @Inject
    SMTPConfig smtpConfig;

    /**
     * Creates a mail session.
     */
    @Produces
    @ApplicationScoped
    Session createMailSession() {
        final Properties prop = new Properties();
        prop.put("mail.smtp.auth", smtpConfig.authEnabled());
        prop.put("mail.smtp.ssl.enable", smtpConfig.sslEnabled());
        prop.put("mail.smtp.host", smtpConfig.host());
        prop.put("mail.smtp.port", smtpConfig.port());
        prop.put("mail.smtp.starttls.enable", smtpConfig.startTlsEnabled());
        prop.put("mail.smtp.ssl.trust",
                smtpConfig.sslTrust() != null && !smtpConfig.sslTrust().isEmpty() ? smtpConfig.sslTrust() : null);

        final Session session = Session.getInstance(prop, new jakarta.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(smtpConfig.user(), smtpConfig.password());
            }
        });
        return session;
    }
}
