package com.github.StefanRichterHuber;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;

import com.github.StefanRichterHuber.MailSenderService.CRLFOutputStream;
import com.github.StefanRichterHuber.MailSenderService.PrivateKeyProvider;
import com.github.StefanRichterHuber.MailSenderService.PublicKeySearchService;
import com.github.StefanRichterHuber.MailSenderService.SMTPConfig;
import com.github.StefanRichterHuber.MailSenderService.SecureMailService;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.inject.Inject;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

@QuarkusTest
public class SecureMailSenderTest {

    @Inject
    SecureMailService secureMailSender;

    @Inject
    SMTPConfig smtpConfig;

    @Inject
    @ConfigProperty(name = "mail.to")
    String to;

    @Inject
    Session session;

    @Inject
    PrivateKeyProvider privateKeyProvider;

    @Test
    public void testCreateInlineSignedMail() throws Exception {
        byte[] recipientCert = PublicKeySearchService.findByMail(to);
        final byte[] senderKey = privateKeyProvider.getPrivateKey(smtpConfig.from());
        var mail = secureMailSender.createInlineSignedMail(new InternetAddress(smtpConfig.from()),
                new InternetAddress(to), "Secure Document", "Here is the requested document.",
                senderKey, recipientCert, session);
        writeMailToDisk(mail, true);
    }

    @Test
    public void testCreateSignedAndEncryptedMail() throws Exception {
        var mail1 = sendMail(true, session);
        var mail2 = sendMail(false, session);

        secureMailSender.addAutocryptHeader(mail1);
        secureMailSender.addAutocryptHeader(mail2);

        // Write to file (or send via Transport)

        writeMailToDisk(mail1, true);
        writeMailToDisk(mail2, false);

    }

    @Test
    void testSendInlineSignedMail() throws Exception {
        byte[] recipientCert = PublicKeySearchService.findByMail(to);
        final byte[] senderKey = privateKeyProvider.getPrivateKey(smtpConfig.from());
        var mail = secureMailSender.createInlineSignedMail(new InternetAddress(smtpConfig.from()),
                new InternetAddress(to), "Secure Document", "Here is the requested document.",
                senderKey, recipientCert, session);
        Transport.send(mail);
    }

    @Test
    public void testSendMail() throws Exception {
        var mail = sendMail(true, session);
        Transport.send(mail);
    }

    private MimeMessage sendMail(boolean withEncryption, Session session) throws Exception {

        byte[] recipientCert = PublicKeySearchService.findByMail(to);

        List<DataSource> attachments = new ArrayList<>();
        attachments.add(new FileDataSource(new File("README.md")));
        // attachments.add(new FileDataSource(new File("pom.xml")));

        MimeMessage mimeMessage = secureMailSender.createSignedMail(new InternetAddress(to),
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