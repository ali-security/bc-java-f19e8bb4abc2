package org.bouncycastle.mime.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.util.Strings;

public class HeadersTest
    extends TestCase
{
    /**
     * Continuation lines were joined with String concatenation, which copies the whole header so
     * far for each line, so parsing a folded header was quadratic in its length: a 1 MB header block
     * of short continuation lines took about 17 seconds. The header block is the message's own
     * bytes and nothing bounds it, so this was attacker-controlled CPU.
     * <p>
     * The check is on how the parse time grows rather than on a wall-clock bound, so it holds on
     * a slow or loaded machine: eight times the continuation lines should cost about eight times
     * as much, where the quadratic version cost about sixty-four times as much.
     */
    public void testLongFoldedHeaderStaysLinear()
        throws IOException
    {
        int small = 25000;
        int large = 8 * small;

        Headers h = new Headers(new ByteArrayInputStream(foldedHeader(large)), "7bit");

        String value = h.getValues("X-Folded")[0];
        assertEquals("start".length() + large * 8, value.length());
        assertTrue(value.startsWith("start12345678"));
        assertTrue(value.endsWith("1234567812345678"));
        assertEquals("text/plain", h.getContentType());

        long smallTime = minParseNanos(foldedHeader(small), 3);
        long largeTime = minParseNanos(foldedHeader(large), 3);

        assertTrue("parse time grew by " + (largeTime / Math.max(smallTime, 1L)) + "x for 8x the continuation lines ("
            + smallTime / 1000000 + "ms, " + largeTime / 1000000 + "ms)", largeTime < 24 * smallTime);
    }

    private static long minParseNanos(byte[] data, int runs)
        throws IOException
    {
        long best = Long.MAX_VALUE;
        for (int i = 0; i != runs; i++)
        {
            long start = System.nanoTime();
            new Headers(new ByteArrayInputStream(data), "7bit");
            best = Math.min(best, System.nanoTime() - start);
        }
        return best;
    }

    private static byte[] foldedHeader(int lines)
    {
        StringBuilder sb = new StringBuilder("Content-Type: text/plain\r\nX-Folded: start\r\n");
        for (int i = 0; i < lines; i++)
        {
            sb.append(" 12345678\r\n");
        }
        sb.append("\r\nbody");

        return Strings.toByteArray(sb.toString());
    }
}
