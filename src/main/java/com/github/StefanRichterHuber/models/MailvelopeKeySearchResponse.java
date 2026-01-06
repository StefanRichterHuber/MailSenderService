package com.github.StefanRichterHuber.models;

import java.util.List;

/*
* Data model for this response from mailevelop key server
* @see  https://github.com/mailvelope/keyserver?tab=readme-ov-file
 */
public record MailvelopeKeySearchResponse(
        String keyId,
        String fingerprint,
        List<UserId> userIds,
        String created,
        String algorithm,
        String keySize,
        String publicKeyArmored) {
    public record UserId(String name, String email, String verified) {
    }
}
