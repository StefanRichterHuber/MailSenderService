package com.github.StefanRichterHuber.MailSenderService;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class CRLFOutputStream extends FilterOutputStream {
    private int lastByte = -1;

    public CRLFOutputStream(OutputStream out) {
        super(out);
    }

    @Override
    public void write(int b) throws IOException {
        if (b == '\r') {
            out.write(b);
        } else if (b == '\n') {
            if (lastByte != '\r') {
                out.write('\r');
            }
            out.write(b);
        } else {
            out.write(b);
        }
        lastByte = b;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        for (int i = off; i < off + len; i++) {
            write(b[i]);
        }
    }
}
