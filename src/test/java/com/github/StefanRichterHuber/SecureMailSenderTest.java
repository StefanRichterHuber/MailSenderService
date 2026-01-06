package com.github.StefanRichterHuber;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.inject.Inject;
import jakarta.mail.internet.MimeMessage;

@QuarkusTest
public class SecureMailSenderTest {

    @Inject
    SecureMailSender secureMailSender;

    @Inject
    SMTPConfig smtpConfig;

    @Test
    public void testSendSignedAndEncryptedMail() throws Exception {
        var mail1 = sendMail(true);
        var mail2 = sendMail(false);

        // Write to file (or send via Transport)

        writeMailToDisk(mail1, true);
        writeMailToDisk(mail2, false);

    }

    private MimeMessage sendMail(boolean withEncryption) throws Exception {

        File senderKeyFile = smtpConfig.senderSecretKeyFile();
        File recipientCertFile = new File("./.keyrings/stefan-keyring.asc"); // Optional

        byte[] senderKey = secureMailSender.extractPrivateKey(Files.readAllBytes(senderKeyFile.toPath()));
        byte[] recipientCert = withEncryption && recipientCertFile.exists()
                ? Files.readAllBytes(recipientCertFile.toPath())
                : null;

        List<DataSource> attachments = new ArrayList<>();
        attachments.add(new FileDataSource(new File("README.md")));
        attachments.add(new FileDataSource(new File("pom.xml")));

        MimeMessage mimeMessage = secureMailSender.createMail("qnap@richter-huber.de", "stefan@richter-huber.de",
                "Secure Document", "Here is the requested document.",
                withEncryption,
                senderKey, withEncryption ? recipientCert : null,
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