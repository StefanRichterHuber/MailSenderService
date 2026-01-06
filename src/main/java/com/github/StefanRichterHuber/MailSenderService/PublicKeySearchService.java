package com.github.StefanRichterHuber.MailSenderService;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import jakarta.enterprise.inject.spi.CDI;

public interface PublicKeySearchService {

    /**
     * Searches for a public key by email. Returns the raw key data.
     * 
     * @param email
     * @return
     */
    public static byte[] findByMail(String email) {
        return CDI.current().select(PublicKeySearchService.class).stream()
                .map(service -> service.searchKeyByEmail(email))
                .filter(v -> v != null).findFirst().orElse(null);
    }

    /**
     * Searches for a public key by email. Returns the raw key data.
     * 
     * @param email
     * @return
     */
    byte[] searchKeyByEmail(String email);

    /**
     * Parses an ASCII Armored OpenPGP key and extracts the raw binary data.
     * This strips the headers, footers, metadata, and CRC checksum.
     *
     * @param armoredKeyBytes The byte array containing the ASCII armored key.
     * @return The raw binary key data.
     * @throws IOException If there is an error reading the byte stream.
     */
    public static byte[] dearmorKey(byte[] armoredKeyBytes) throws IOException {
        final BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(armoredKeyBytes), StandardCharsets.US_ASCII));

        final StringBuilder base64Content = new StringBuilder();
        String line;
        boolean inBlock = false;
        boolean headersFinished = false;

        while ((line = reader.readLine()) != null) {
            String trimmed = line.trim();

            // 1. Detect Start of Block
            if (trimmed.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
                inBlock = true;
                continue;
            }

            // 2. Detect End of Block
            if (trimmed.startsWith("-----END PGP PUBLIC KEY BLOCK-----")) {
                break;
            }

            if (!inBlock)
                continue;

            // 3. Skip Metadata Headers (e.g. "Version: ...")
            // Headers are separated from the Base64 body by an empty line.
            if (!headersFinished) {
                if (trimmed.isEmpty()) {
                    headersFinished = true;
                }
                continue;
            }

            // 4. Skip CRC Checksum
            // The checksum is the last line of the body and starts with '=' (e.g., =abcd)
            if (trimmed.startsWith("=")) {
                continue;
            }

            // 5. Append Base64 Data
            base64Content.append(trimmed);
        }

        if (base64Content.length() == 0) {
            throw new IllegalArgumentException("Invalid key file: No PGP data found.");
        }

        // 6. Decode the clean Base64 string to raw bytes
        return Base64.getDecoder().decode(base64Content.toString());
    }
}
