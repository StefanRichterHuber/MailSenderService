package com.github.StefanRichterHuber;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.inject.Inject;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

@QuarkusTest
public class SecureMailSenderTest {

    @Inject
    SecureMailSender secureMailSender;

    @Inject
    SMTPConfig smtpConfig;

    @Test
    public void testSendSignedAndEncryptedMail() throws Exception {
        Session session = Session.getDefaultInstance(new Properties());
        var mail1 = sendMail(true, session);
        var mail2 = sendMail(false, session);

        secureMailSender.addAutocryptHeader(mail1);
        secureMailSender.addAutocryptHeader(mail2);

        // Write to file (or send via Transport)

        writeMailToDisk(mail1, true);
        writeMailToDisk(mail2, false);

    }

    @Test
    public void actuallSendMail() throws Exception {
        Properties prop = new Properties();
        prop.put("mail.smtp.auth", smtpConfig.authEnabled());
        prop.put("mail.smtp.ssl.enable", smtpConfig.sslEnabled());
        prop.put("mail.smtp.host", smtpConfig.host());
        prop.put("mail.smtp.port", smtpConfig.port());
        prop.put("mail.smtp.starttls.enable", smtpConfig.startTlsEnabled());
        prop.put("mail.smtp.ssl.trust",
                smtpConfig.sslTrust() != null && !smtpConfig.sslTrust().isEmpty() ? smtpConfig.sslTrust() : null);

        Session session = Session.getInstance(prop, new jakarta.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(smtpConfig.user(), smtpConfig.password());
            }
        });

        var mail = sendMail(true, session);
        Transport.send(mail);
    }

    private MimeMessage sendMail(boolean withEncryption, Session session) throws Exception {

        byte[] recipientCert = PublicKeySearchService.findByMail("stefan@richter-huber.de");

        List<DataSource> attachments = new ArrayList<>();
        attachments.add(new FileDataSource(new File("README.md")));
        attachments.add(new FileDataSource(new File("pom.xml")));

        MimeMessage mimeMessage = secureMailSender.createSignedMail(new InternetAddress("stefan@richter-huber.de"),
                "Secure Document", "Here is the requested document.",
                withEncryption ? recipientCert : null,
                attachments, session);

        return mimeMessage;
    }

    private void writeMailToDisk(MimeMessage message, boolean withEncryption) throws Exception {
        try (OutputStream out = new CRLFOutputStream(withEncryption ? new FileOutputStream("signed_encrypted_email.eml")
                : new FileOutputStream("signed_email.eml"))) {
            message.writeTo(out);
        }
        System.out.println("Email generated: " + (withEncryption ? "signed_encrypted_email.eml" : "signed_email.eml"));
    }

}