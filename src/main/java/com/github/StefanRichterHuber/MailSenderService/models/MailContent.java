package com.github.StefanRichterHuber.MailSenderService.models;

import java.util.Collection;
import java.util.Set;

import jakarta.activation.DataSource;
import jakarta.mail.internet.MimeBodyPart;

public record MailContent(String from, Set<String> to, Set<String> cc, Set<String> bcc, String subject,
        Collection<MimeBodyPart> bodies, Collection<DataSource> attachments,
        SignatureVerificationResult signatureVerified) {

    public static enum SignatureVerificationResult {
        NoSignature,
        SignatureVerified,
        SignatureInvalid
    }
}