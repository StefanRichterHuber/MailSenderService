package com.github.StefanRichterHuber.MailSenderService.models;

import java.util.Collection;

import jakarta.activation.DataSource;
import jakarta.mail.internet.MimeBodyPart;

public record MailContent(String from, String to, String subject, Collection<MimeBodyPart> bodies,
        Collection<DataSource> attachments, SignatureVerificationResult signatureVerified) {

    public static enum SignatureVerificationResult {
        NoSignature,
        SignatureVerified,
        SignatureInvalid
    }
}