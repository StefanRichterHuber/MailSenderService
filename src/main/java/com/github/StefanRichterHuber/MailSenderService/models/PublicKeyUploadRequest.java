package com.github.StefanRichterHuber.MailSenderService.models;

/**
 * A request to upload a public key to the Mailvelope key server. Starts with
 * the prefix "-----BEGIN PGP PUBLIC KEY BLOCK-----"
 */
public record PublicKeyUploadRequest(String publicKeyArmored) {
}