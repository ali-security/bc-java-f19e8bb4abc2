package org.bouncycastle.cert.crmf;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.util.Strings;

public class PKMACBuilder
{
    private AlgorithmIdentifier owf;
    private int iterationCount;
    private AlgorithmIdentifier mac;
    private int saltLength = 20;
    private SecureRandom random;
    private PKMACValuesCalculator calculator;
    private PBMParameter parameters;
    private int maxIterations;

    public PKMACBuilder(PKMACValuesCalculator calculator)
    {
        this(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), 1000, new AlgorithmIdentifier(IANAObjectIdentifiers.hmacSHA1, DERNull.INSTANCE), calculator);
    }

    /**
     * Create a PKMAC builder enforcing a ceiling on the maximum iteration count.
     *
     * @param calculator     supporting calculator
     * @param maxIterations  max allowable value for iteration count.
     */
    public PKMACBuilder(PKMACValuesCalculator calculator, int maxIterations)
    {
        this.maxIterations = maxIterations;
        this.calculator = calculator;
    }

    private PKMACBuilder(AlgorithmIdentifier hashAlgorithm, int iterationCount, AlgorithmIdentifier macAlgorithm, PKMACValuesCalculator calculator)
    {
        this.owf = hashAlgorithm;
        this.iterationCount = iterationCount;
        this.mac = macAlgorithm;
        this.calculator = calculator;
    }

    /**
     * Set the salt length in octets.
     *
     * @param saltLength length in octets of the salt to be generated.
     * @return the generator
     */
    public PKMACBuilder setSaltLength(int saltLength)
    {
        if (saltLength < 8)
        {
            throw new IllegalArgumentException("salt length must be at least 8 bytes");
        }

        this.saltLength = saltLength;

        return this;
    }

    public PKMACBuilder setIterationCount(int iterationCount)
    {
        if (iterationCount < 100)
        {
            throw new IllegalArgumentException("iteration count must be at least 100");
        }
        checkIterationCountCeiling(iterationCount);

        this.iterationCount = iterationCount;

        return this;
    }

    public PKMACBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public PKMACBuilder setParameters(PBMParameter parameters)
    {
        checkIterationCountCeiling(parameters.getIterationCount().intValueExact());

        this.parameters = parameters;

        return this;
    }

    public MacCalculator build(char[] password)
        throws CRMFException
    {
        if (parameters != null)
        {
            return genCalculator(parameters, password);
        }
        else
        {
            byte[] salt = new byte[saltLength];

            if (random == null)
            {
                this.random = new SecureRandom();
            }

            random.nextBytes(salt);

            return genCalculator(new PBMParameter(salt, owf, iterationCount, mac), password);
        }
    }

    private void checkIterationCountCeiling(int iterationCount)
    {
        // When no explicit ceiling was configured, fall back to a generous default so that an
        // attacker-supplied PBMParameter from an incoming CMP message (verified via the get(...)
        // entry point) cannot drive the iterated hash in genCalculator into a CPU-exhaustion DoS.
        int ceiling = maxIterations > 0
            ? maxIterations
            : maxIterationCount();
        if (iterationCount > ceiling)
        {
            throw new IllegalArgumentException("iteration count exceeds limit (" + iterationCount + " > " + ceiling + ")");
        }
    }

    private MacCalculator genCalculator(final PBMParameter params, char[] password)
        throws CRMFException
    {
        // From RFC 4211
        //
        //   1.  Generate a random salt value S
        //
        //   2.  Append the salt to the pw.  K = pw || salt.
        //
        //   3.  Hash the value of K.  K = HASH(K)
        //
        //   4.  Iter = Iter - 1.  If Iter is greater than zero.  Goto step 3.
        //
        //   5.  Compute an HMAC as documented in [HMAC].
        //
        //       MAC = HASH( K XOR opad, HASH( K XOR ipad, data) )
        //
        //       Where opad and ipad are defined in [HMAC].
        byte[] pw = Strings.toUTF8ByteArray(password);
        byte[] salt = params.getSalt().getOctets();
        byte[] K = new byte[pw.length + salt.length];

        System.arraycopy(pw, 0, K, 0, pw.length);
        System.arraycopy(salt, 0, K, pw.length, salt.length);

        calculator.setup(params.getOwf(), params.getMac());

        int iter = params.getIterationCount().intValueExact();
        do
        {
            K = calculator.calculateDigest(K);
        }
        while (--iter > 0);

        final byte[] key = K;

        return new MacCalculator()
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, params);
            }

            public GenericKey getKey()
            {
                return new GenericKey(getAlgorithmIdentifier(), key);
            }

            public OutputStream getOutputStream()
            {
                return bOut;
            }

            public byte[] getMac()
            {
                try
                {
                    return calculator.calculateMac(key, bOut.toByteArray());
                }
                catch (CRMFException e)
                {
                    throw new RuntimeOperatorException("exception calculating mac: " + e.getMessage(), e);
                }
            }
        };
    }

    /**
     * Upper bound on the RFC 4211 PKMAC / CMP password-based-MAC iteration count honoured when no
     * explicit ceiling was supplied. The count travels in the (unauthenticated) PBMParameter of an
     * incoming CMP message and drives an iterated hash, so an unbounded count makes verifying an
     * attacker-supplied message a CPU-exhaustion vector. Default 10,000,000, generous enough for
     * any legitimate setting.
     */
    private static final String PKMAC_MAX_ITERATION_COUNT = "org.bouncycastle.pkmac.max_iteration_count";
    private static final int DEFAULT_MAX_ITERATION_COUNT = 10000000;

    private static int maxIterationCount()
    {
        // Read directly rather than through org.bouncycastle.util.Properties: that class is
        // shipped by the provider jar, which is resolved independently of this one.
        String p = (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            // JDK 1.4 compatibility
            public Object run()
            {
                try
                {
                    return System.getProperty(PKMAC_MAX_ITERATION_COUNT);
                }
                catch (AccessControlException e)
                {
                    return null;
                }
            }
        });

        if (p != null)
        {
            return Integer.parseInt(p);
        }

        return DEFAULT_MAX_ITERATION_COUNT;
    }
}
