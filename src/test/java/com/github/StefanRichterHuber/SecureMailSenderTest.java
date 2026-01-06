package com.github.StefanRichterHuber;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.inject.Inject;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

@QuarkusTest
public class SecureMailSenderTest {

    @Inject
    SecureMailSender secureMailSender;

    @Test
    public void testSendSignedAndEncryptedMail() throws Exception {
        var mail1 = sendMail(true);
        var mail2 = sendMail(false);

        secureMailSender.addAutocryptHeader(mail1);
        secureMailSender.addAutocryptHeader(mail2);

        // Write to file (or send via Transport)

        writeMailToDisk(mail1, true);
        writeMailToDisk(mail2, false);

    }

    private MimeMessage sendMail(boolean withEncryption) throws Exception {

        byte[] recipientCert = null;

        // Lookup cert
        recipientCert = PublicKeySearchService.findByMail("stefan@richter-huber.de").orElse(null);

        List<DataSource> attachments = new ArrayList<>();
        attachments.add(new FileDataSource(new File("README.md")));
        attachments.add(new FileDataSource(new File("pom.xml")));

        MimeMessage mimeMessage = secureMailSender.createSignedMail(new InternetAddress("stefan@richter-huber.de"),
                "Secure Document", "Here is the requested document.",
                withEncryption ? recipientCert : null,
                attachments);

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