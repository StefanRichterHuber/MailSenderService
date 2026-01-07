package com.github.StefanRichterHuber.MailSenderService;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.jboss.resteasy.reactive.RestForm;
import org.jboss.resteasy.reactive.multipart.FileUpload;

import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

@Path("/sendmail")
@ApplicationScoped
public class MailSendResource {

    @Inject
    SecureMailService mailFactory;

    @POST
    public void multipart(
            @RestForm String to,
            @RestForm String subject,
            @RestForm String body,
            @RestForm boolean sign,
            @RestForm boolean encrypt,
            @RestForm(FileUpload.ALL) List<FileUpload> files) throws AddressException, Exception {

        // Convert all FileUpload to DataSource
        final List<DataSource> attachments = files != null ? files.stream()
                .map(this::toDataSource)
                .collect(Collectors.toList()) : Collections.emptyList();

        mailFactory.sendMail(new InternetAddress(to), subject, body, sign, encrypt, attachments);
    }

    private DataSource toDataSource(FileUpload fileUpload) {
        return new FileDataSource(fileUpload.filePath().toFile());
    }
}
