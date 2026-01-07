package com.github.StefanRichterHuber;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.github.StefanRichterHuber.MailSenderService.CRLFOutputStream;
import com.github.StefanRichterHuber.MailSenderService.SMTPConfig;
import com.github.StefanRichterHuber.MailSenderService.SecureMailService;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.inject.Inject;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

@QuarkusTest
public class SecureMailSenderTest {

    @Inject
    SecureMailService secureMailSender;

    @Inject
    @ConfigProperty(name = "mail.to")
    String to;

    @Test
    public void testCreateInlineSignedMail() throws Exception {
        var mail = sendMail(true, true);
        writeMailToDisk(mail, true, true);
    }

    @Test
    public void testCreateSignedAndEncryptedMail() throws Exception {
        var mail1 = sendMail(true, false);
        var mail2 = sendMail(false, false);

        secureMailSender.addAutocryptHeader(mail1);
        secureMailSender.addAutocryptHeader(mail2);

        // Write to file (or send via Transport)

        writeMailToDisk(mail1, true, false);
        writeMailToDisk(mail2, false, false);

    }

    @Test
    @Disabled("Really sends a mail")
    void testSendInlineSignedMail() throws Exception {
        var mail = sendMail(true, true);
        Transport.send(mail);
    }

    @Test
    @Disabled("Really sends a mail")
    public void testSendMail() throws Exception {
        var mail = sendMail(true, false);
        Transport.send(mail);
    }

    private MimeMessage sendMail(boolean withEncryption, boolean inline) throws Exception {
        List<DataSource> attachments = new ArrayList<>();
        attachments.add(new FileDataSource(new File("README.md")));
        // attachments.add(new FileDataSource(new File("pom.xml")));

        MimeMessage mimeMessage = secureMailSender.createPGPMail(new InternetAddress(to),
                "Secure Document", "Here is the requested document.", true,
                withEncryption, false, inline,
                attachments);

        return mimeMessage;
    }

    private void writeMailToDisk(MimeMessage message, boolean withEncryption, boolean inline) throws Exception {
        String filename = withEncryption ? "signed_encrypted_email.eml" : "signed_email.eml";
        if (inline) {
            filename = "inline_" + filename;
        }

        try (OutputStream out = new CRLFOutputStream(new FileOutputStream(filename))) {
            message.writeTo(out);
        }
        System.out.println("Email generated: " + filename);
    }

}