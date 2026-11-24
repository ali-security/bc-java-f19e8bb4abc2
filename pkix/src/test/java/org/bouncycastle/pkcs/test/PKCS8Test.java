package org.bouncycastle.pkcs.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.util.PBKDFConfig;
import org.bouncycastle.crypto.util.ScryptConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

public class PKCS8Test
    extends TestCase
{
    private static final String PBE_MAX_ITERATION_COUNT = "org.bouncycastle.pbe.max_iteration_count";
    private static final String PBE_MAX_SCRYPT_MEMORY = "org.bouncycastle.pbe.max_scrypt_memory";
    private static final String PKCS12_MAX_IT_COUNT = "org.bouncycastle.pkcs12.max_it_count";

    private static final char[] passwd = "hello".toCharArray();

    private static BigInteger modulus = new BigInteger(
        "b6ce33ccbf839457b0d32487b6c807bca584f85c627466b787fc09d0b1f73d97c9a381eca20e0ba851d317a8964327fa0010de76c" +
            "6c0facb83f13612752d166b49d9ba272c38c9a4ed71a94ea69f7bbdc63d7a5c5d3f3c039223e4ac1bb5d433c6bf01e68364a7ef4f" +
            "061f7cdfba82fa471bb1444b2034e53cc9c3e402a8fa89", 16);

    private static byte[] pkInfo = Base64.decode(
        "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALbOM8y/g5RXsNMkh7bIB7ylhPhcYnRmt4f8CdCx9z2XyaOB7KIOC6hR" +
            "0xeolkMn+gAQ3nbGwPrLg/E2EnUtFmtJ2bonLDjJpO1xqU6mn3u9xj16XF0/PAOSI+SsG7XUM8a/AeaDZKfvTwYffN+6gvpHG7FESyA0" +
            "5TzJw+QCqPqJAgMBAAECgYAMQxCeb0o4LRmjUBP6YriCIugkcK35+NneuT0/TnCzJPdVjGV/CUom5DYwpBJQNuJCFt+VQAe5yuTyzRm3" +
            "2mpicusxKsMHqJRJFWIQ5ztuRehGF1KB+NPze7GxWVB2vRWJQQhlgq/nRsAjWoUfxbFkKBlNPhUnLm1klwBptpqpcQJBAOBiAnrrraBu" +
            "3Lc9B8QtCdEAIr5LYyWYd3jSvyTt04OI8Q3l7zG9omKpdIskGNu7n5RRYixsNXAVCaiHsyHHCO8CQQDQkGdtlH5fQZ2PJVSNZ6RlDhUq" +
            "6RGqajnkXw/sK1GR388FGqc9xTB9Eu1vg7ywlsuWSWpiCe/q+1nGVJufLAQHAkEAyTba5oQGNYJ1J1Txa/i/fs7SWTedd49cQ9spUeJ7" +
            "9M6O7FmvwDlAL52qR0Rdjl6YYhcBJLj8yr/y41CdUML9vQJAYGDqurOtNj2vHrAkg3fKezxnwb2UgUi3WfYn+H4IIr3m/7fSYvQVtSai" +
            "/C5Hat80U0230HhBGzhtwv3kMEj5zwJAViD4ceQRYyC+G2z5fyFz8Ca6sjDB9LwY0YEOFxR+3nqtteJI2vgITl4HrrnTRGuiVSY6pqkX" +
            "hX2DZcWDZMieLA==");

    private static byte[] pkcs8Sha256 = Base64.decode(
    "MIIC9TBvBgkqhkiG9w0BBQ0wYjBBBgkqhkiG9w0BBQwwNAQgsa99yy9MqsJQ+4l5" +
        "SehvabVidNKBoJeqPJDZAPmbKCgCAggAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUD" +
        "BAEqBBBAncGTD5Yp0oqVklTgmzt4BIICgDJLy5EF12+l9cjYIRVLcHFc7QE7prBy" +
        "yj+nENvxqPJaVAVo+VVguOPUSGKQAeZnUhpU1kwKa4EyUhA5CvVtTcQ3hd7v769E" +
        "n59EJ2NKFNOmplxbE3QU/Z7g63ECDvu4jsUVjZmWGrzDXwDEkraG5VdtVhIfdFOj" +
        "yR1CEnxLqq5l3qlkCjKFap/UBh6wbsItJJYw4HJ/7fCJtY8xKG9b1hxHiyH2Yhrh" +
        "Pak2P4ukFClg8Kzv92ZbUKSv92C/zrlkUWx7+u7b97YZVd/nL4VLVnQW79YI7ApL" +
        "QHFNZ9Jp3cm3XtddzlJJVWwghF+slvULsGzQ05yMICyCRHEwPAPSXvf6VpNezQ+v" +
        "8mD+lS7IavJRx7S4y2NFzZCLDaZfX32/S4vRv7Q4Ax87YKHqHwLnZRLWn3QimtX5" +
        "oJPsf8Sj0/w31W49c7I3a4rWLAWO3fTVSvH+vQdPUCq9geqatOjiwSnUy6oSP4f3" +
        "vvdMlvNFafWyLwqONM8nKijNSSk8fjJtncvIDBCRYmwuQFmkFBRtCpHNeY43vrCV" +
        "O04x5N6PPTnnp/Ru7xYbrEyO2SQX/JJQV2l/pZgyF4w/2Y3i0hW+dItkoFVPGuY0" +
        "XfBgPlVx5w/72Et8GKh8a5E03IPJOa3J+/vhx9hYc7Hc4AJHsQQwiXco5ybBNZBV" +
        "wteKQwP6XRL5GMWJr4v4fJk0ksZ7sDAIlLWOeZu0jxWSx3VLC6QR9Ij+uMGkkY3t" +
        "nVxJii5qFSnWSH5e2Qk9HJ64a0ossKBFaln8wT/2tryBxa1+YZDYwGrasG4EvKHC" +
        "N0PVvCZ6nreGoWpaBlTolOl7HpbjcsryQ2SMkWNIurrivWKAoqRQ53Q=");


    private static byte[] pkcs8Gost3411 = Base64.decode(
        "MIIC8zBtBgkqhkiG9w0BBQ0wYDA/BgkqhkiG9w0BBQwwMgQgo40hf88LUYklfxUE" +
            "HO0KjJFo52p9lEqfYDDmJJosDpYCAggAMAoGBiqFAwICCgUAMB0GCWCGSAFlAwQB" +
            "KgQQJXNzoxem4QvtoToJbJVt1ASCAoBtcnpMvp/Skip+m8e0A+Hh8BnzoRDkKoeD" +
            "QFuyR1HRfXa6iZ+CT5Bt38kM7shDA1se1uEo5WnDCydmzQ5WdHinMaokryd+3l65" +
            "AszZLrbK56E78820RMTwFevDAXcwhneomCkEg059r+GfO0OLe6YJ1JR88uiPWxJy" +
            "gthltJoefOnK87cG53oOPAmgKkMS0lbd13FeYduo9r2473O80CtTpA0p5GHFHdI8" +
            "9ebu8PWoGez+HR3FU5+m4Qj63spW2F1qblgocywABFqVCWVp/8h4dptQ7754jNmK" +
            "HN4MWgXYb5SdScz8IkE9Cv+Xn0tAW5eqhgYDot4GfbYRqCjup0jnCmgNxFo/TMOS" +
            "H1EMXeFnEEEft/fx8K1jZ1jtfJQRBY1N0jOBBzsMKVgj8GYkFAlOYXziCK+YzYjY" +
            "gmD2/IQ1+VfPnCkT14BqM9KzJidOjMDE9jlMiBhaBzee0qpdCLZ9bPQ0L6s6Urwm" +
            "mR7l1nCvLY5GYRBUC/ZOZf+MiPEpD/Lu+DUv5RgPEDStSXoKqtxvgpsT4upDVpEw" +
            "i4z7TWGpkcOGZJEe8JHEw5rDC15FHm44WoeFhlgLaFhjUD9Ou4CYM3LYT6VwUbmF" +
            "XBBVuKssFbbvOcU1ez4vfx7i8r09R/olVmopsiUBapyLwfck3hlQEYrAJKHQ9HFV" +
            "qYM9tU0OoaZB1qYYmLQPIe99cr66xTmfUkRQaJ2RAhbZQDPTX3Bm4SseEfmrkfuY" +
            "/RzOT5l2cgEOuTmkzhfgxVqyhOBeWfGPWYWtDD2QmQBcAHZbf9XVaoRe7YDRXTG/" +
            "WhEN3fKJaM/Qfif5wwWvHjQb5TWrTyeNNuh4YtXsyQ3PkwOxHrmm"
    );

    // from RFC 7914
    private static byte[] pkcs8Scrypt = Base64.decode(
        "MIHiME0GCSqGSIb3DQEFDTBAMB8GCSsGAQQB2kcECzASBAVNb3VzZQIDEAAAAgEI" +
            "AgEBMB0GCWCGSAFlAwQBKgQQyYmguHMsOwzGMPoyObk/JgSBkJb47EWd5iAqJlyy" +
            "+ni5ftd6gZgOPaLQClL7mEZc2KQay0VhjZm/7MbBUNbqOAXNM6OGebXxVp6sHUAL" +
            "iBGY/Dls7B1TsWeGObE0sS1MXEpuREuloZjcsNVcNXWPlLdZtkSH6uwWzR0PyG/Z" +
            "+ZXfNodZtd/voKlvLOw5B3opGIFaLkbtLZQwMiGtl42AS89lZg=="
    );

    private static byte[] scryptKey = Base64.decode(
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4RaNK5CuHY3CXr9f" +
            "/CdVgOhEurMohrQmWbbLZK4ZInyhRANCAARs2WMV6UMlLjLaoc0Dsdnj4Vlffc9T" +
            "t48lJU0RiCzXc280Vg/H5fm1xAP1B7UnIVcBqgDHDcfqWm1h/xSeCHXS"
    );

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testSHA256()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo info = new PKCS8EncryptedPrivateKeyInfo(pkcs8Sha256);
        
        PrivateKeyInfo pkInfo = info.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("hello".toCharArray()));

        RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

        assertEquals(modulus, k.getModulus());
    }

    public void testGOST3411()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo info = new PKCS8EncryptedPrivateKeyInfo(pkcs8Gost3411);

        PrivateKeyInfo pkInfo = info.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("hello".toCharArray()));

        RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

        assertEquals(modulus, k.getModulus());
    }

    public void testScrypt()
        throws Exception
    {
        if (getJvmVersion() < 7)  // runs out of memory
        {
            return;
        }
        
        PKCS8EncryptedPrivateKeyInfo info = new PKCS8EncryptedPrivateKeyInfo(pkcs8Scrypt);

        PrivateKeyInfo pkInfo = info.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray()));
        
        assertTrue(Arrays.areEqual(scryptKey, pkInfo.getEncoded()));
    }

    public void testSHA256Encryption()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfoBuilder bldr = new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo);

        PKCS8EncryptedPrivateKeyInfo encInfo = bldr.build(
            new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                .setPRF(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))
                .setProvider("BC")
                .build("hello".toCharArray()));

        EncryptedPrivateKeyInfo encPkInfo = EncryptedPrivateKeyInfo.getInstance(encInfo.getEncoded());

        assertEquals(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE),
            PBKDF2Params.getInstance(
                PBES2Parameters.getInstance(encPkInfo.getEncryptionAlgorithm().getParameters())
                    .getKeyDerivationFunc().getParameters())
                .getPrf());

        PrivateKeyInfo pkInfo = encInfo.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("hello".toCharArray()));

        RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

        assertEquals(modulus, k.getModulus());
    }

    public void testSHA3_256Encryption()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfoBuilder bldr = new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo);

        PKCS8EncryptedPrivateKeyInfo encInfo = bldr.build(
            new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                .setPRF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_256, DERNull.INSTANCE))
                .setProvider("BC")
                .build("hello".toCharArray()));

        EncryptedPrivateKeyInfo encPkInfo = EncryptedPrivateKeyInfo.getInstance(encInfo.getEncoded());

        assertEquals(
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_256, DERNull.INSTANCE),
            PBKDF2Params.getInstance(
                PBES2Parameters.getInstance(encPkInfo.getEncryptionAlgorithm().getParameters())
                    .getKeyDerivationFunc().getParameters())
                .getPrf());

        PrivateKeyInfo pkInfo = encInfo.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("hello".toCharArray()));

        RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

        assertEquals(modulus, k.getModulus());
    }

    public void testKWPEncryption()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfoBuilder bldr = new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo);

        PKCS8EncryptedPrivateKeyInfo encInfo = bldr.build(
            new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes128_wrap_pad)
                .setPRF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_256, DERNull.INSTANCE))
                .setProvider("BC")
                .build("hello".toCharArray()));

        EncryptedPrivateKeyInfo encPkInfo = EncryptedPrivateKeyInfo.getInstance(encInfo.getEncoded());

        assertEquals(
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_256, DERNull.INSTANCE),
            PBKDF2Params.getInstance(
                PBES2Parameters.getInstance(encPkInfo.getEncryptionAlgorithm().getParameters())
                    .getKeyDerivationFunc().getParameters())
                .getPrf());

        PrivateKeyInfo pkInfo = encInfo.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("hello".toCharArray()));

        RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

        assertEquals(modulus, k.getModulus());
    }

    public void testCCMEncryption()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfoBuilder bldr = new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo);

        PKCS8EncryptedPrivateKeyInfo encInfo = bldr.build(
            new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes192_CCM)
                .setPRF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_256, DERNull.INSTANCE))
                .setProvider("BC")
                .build("hello".toCharArray()));

        EncryptedPrivateKeyInfo encPkInfo = EncryptedPrivateKeyInfo.getInstance(encInfo.getEncoded());

        assertEquals(
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_256, DERNull.INSTANCE),
            PBKDF2Params.getInstance(
                PBES2Parameters.getInstance(encPkInfo.getEncryptionAlgorithm().getParameters())
                    .getKeyDerivationFunc().getParameters())
                .getPrf());

        PrivateKeyInfo pkInfo = encInfo.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("hello".toCharArray()));

        RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

        assertEquals(modulus, k.getModulus());
    }

    public void testGCMEncryption()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfoBuilder bldr = new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo);

        PKCS8EncryptedPrivateKeyInfo encInfo = bldr.build(
            new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_GCM)
                .setPRF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_256, DERNull.INSTANCE))
                .setProvider("BC")
                .build("hello".toCharArray()));

        EncryptedPrivateKeyInfo encPkInfo = EncryptedPrivateKeyInfo.getInstance(encInfo.getEncoded());

        assertEquals(
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_256, DERNull.INSTANCE),
            PBKDF2Params.getInstance(
                PBES2Parameters.getInstance(encPkInfo.getEncryptionAlgorithm().getParameters())
                    .getKeyDerivationFunc().getParameters())
                .getPrf());

        PrivateKeyInfo pkInfo = encInfo.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("hello".toCharArray()));

        RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

        assertEquals(modulus, k.getModulus());
    }

    public void testScryptEncryption()
        throws Exception
    {
        if (getJvmVersion() < 7)      // runs out of memory
        {
            return;
        }

        PKCS8EncryptedPrivateKeyInfoBuilder bldr = new PKCS8EncryptedPrivateKeyInfoBuilder(scryptKey);

        PBKDFConfig scrypt = new ScryptConfig.Builder(1048576, 8, 1)
                                        .withSaltLength(20).build();

        PKCS8EncryptedPrivateKeyInfo encInfo = bldr.build(
            new JcePKCSPBEOutputEncryptorBuilder(scrypt, NISTObjectIdentifiers.id_aes256_CBC)
                .setProvider("BC")
                .build("Rabbit".toCharArray()));

        EncryptedPrivateKeyInfo encPkInfo = EncryptedPrivateKeyInfo.getInstance(encInfo.getEncoded());

        PKCS8EncryptedPrivateKeyInfo info = new PKCS8EncryptedPrivateKeyInfo(encPkInfo);

        PrivateKeyInfo pkInfo = info.decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray()));

        assertTrue(Arrays.areEqual(scryptKey, pkInfo.getEncoded()));
    }

    /**
     * Produce a PBES2/PBKDF2 protected private key using the writer's default iteration count.
     */
    private PKCS8EncryptedPrivateKeyInfo encryptPrivateKeyInfo()
        throws Exception
    {
        return new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo).build(
            new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                .setProvider("BC")
                .build(passwd));
    }

    /**
     * Produce a PKCS#12-PBE protected private key using the writer's default iteration count.
     */
    private PKCS8EncryptedPrivateKeyInfo encryptPKCS12PbePrivateKeyInfo()
        throws Exception
    {
        return new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo).build(
            new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                .setProvider("BC")
                .build(passwd));
    }

    /**
     * Rebuild an encrypted key with an attacker chosen PBKDF2 iteration count (and, optionally,
     * an explicit prf), re-encoding it so the guard is exercised against parsed key material.
     */
    private static PKCS8EncryptedPrivateKeyInfo withKdfParams(
        PKCS8EncryptedPrivateKeyInfo encInfo,
        ASN1Integer iterationCount,
        AlgorithmIdentifier prf)
        throws IOException
    {
        EncryptedPrivateKeyInfo info = encInfo.toASN1Structure();
        PBES2Parameters pbeParams = PBES2Parameters.getInstance(info.getEncryptionAlgorithm().getParameters());
        PBKDF2Params kdfParams = PBKDF2Params.getInstance(pbeParams.getKeyDerivationFunc().getParameters());

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DEROctetString(kdfParams.getSalt()));
        v.add(iterationCount);
        if (prf != null)
        {
            v.add(prf);
        }

        PBES2Parameters rebuilt = new PBES2Parameters(
            new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new DERSequence(v)),
            pbeParams.getEncryptionScheme());

        EncryptedPrivateKeyInfo tampered = new EncryptedPrivateKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, rebuilt), info.getEncryptedData());

        return new PKCS8EncryptedPrivateKeyInfo(tampered.getEncoded());
    }

    /**
     * Rebuild a PBES2/scrypt protected key with attacker chosen scrypt cost (N) and block size (r).
     */
    private static PKCS8EncryptedPrivateKeyInfo withScryptParams(
        PKCS8EncryptedPrivateKeyInfo encInfo,
        BigInteger costParameter,
        BigInteger blockSize)
        throws IOException
    {
        return withScryptParams(encInfo, costParameter, blockSize, null);
    }

    /**
     * Rebuild a PBES2/scrypt protected key with attacker chosen scrypt cost (N), block size (r) and,
     * when non-null, parallelization parameter (p).
     */
    private static PKCS8EncryptedPrivateKeyInfo withScryptParams(
        PKCS8EncryptedPrivateKeyInfo encInfo,
        BigInteger costParameter,
        BigInteger blockSize,
        BigInteger parallelization)
        throws IOException
    {
        EncryptedPrivateKeyInfo info = encInfo.toASN1Structure();
        PBES2Parameters pbeParams = PBES2Parameters.getInstance(info.getEncryptionAlgorithm().getParameters());
        assertEquals(MiscObjectIdentifiers.id_scrypt, pbeParams.getKeyDerivationFunc().getAlgorithm());
        ScryptParams scrypt = ScryptParams.getInstance(pbeParams.getKeyDerivationFunc().getParameters());

        PBES2Parameters rebuilt = new PBES2Parameters(
            new KeyDerivationFunc(MiscObjectIdentifiers.id_scrypt,
                new ScryptParams(scrypt.getSalt(), costParameter, blockSize,
                    parallelization != null ? parallelization : scrypt.getParallelizationParameter(), scrypt.getKeyLength())),
            pbeParams.getEncryptionScheme());

        EncryptedPrivateKeyInfo tampered = new EncryptedPrivateKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, rebuilt), info.getEncryptedData());

        return new PKCS8EncryptedPrivateKeyInfo(tampered.getEncoded());
    }

    /**
     * Rebuild a PKCS#12-PBE / PBES1 protected key (both carry SEQUENCE { salt, iterationCount })
     * with an attacker chosen iteration count.
     */
    private static PKCS8EncryptedPrivateKeyInfo withPbeIterationCount(
        PKCS8EncryptedPrivateKeyInfo encInfo,
        ASN1Integer iterationCount)
        throws IOException
    {
        EncryptedPrivateKeyInfo info = encInfo.toASN1Structure();
        AlgorithmIdentifier algId = info.getEncryptionAlgorithm();
        ASN1Sequence params = ASN1Sequence.getInstance(algId.getParameters());

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(params.getObjectAt(0));
        v.add(iterationCount);

        EncryptedPrivateKeyInfo tampered = new EncryptedPrivateKeyInfo(
            new AlgorithmIdentifier(algId.getAlgorithm(), new DERSequence(v)), info.getEncryptedData());

        return new PKCS8EncryptedPrivateKeyInfo(tampered.getEncoded());
    }

    private static void checkDecryptRejected(
        PKCS8EncryptedPrivateKeyInfo encInfo,
        InputDecryptorProvider decryptorProvider,
        String expected)
    {
        try
        {
            encInfo.decryptPrivateKeyInfo(decryptorProvider);
            fail("excessive key-derivation cost accepted");
        }
        catch (PKCSException e)
        {
            assertTrue("unexpected message: " + e.getMessage(), e.getMessage().indexOf(expected) >= 0);
        }
    }

    /**
     * A sane iteration count must still round-trip - the bound may not break normal use.
     */
    public void testPbkdf2RoundTrip()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = encryptPrivateKeyInfo();

        PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd));

        assertTrue(Arrays.areEqual(pkInfo, info.getEncoded()));

        info = encInfo.decryptPrivateKeyInfo(
            new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd));

        assertTrue(Arrays.areEqual(pkInfo, info.getEncoded()));
    }

    public void testPbkdf2IterationCountBound()
        throws Exception
    {
        // The PBES2/PBKDF2 iteration count travels in the unauthenticated encrypted-key container,
        // so it must be bounded before the key-derivation runs. Encrypt with the writer's default
        // count, then decrypt with the bound lowered below it: decryption must be rejected before
        // the derivation rather than honouring an attacker-chosen cost.
        PKCS8EncryptedPrivateKeyInfo encInfo = new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo).build(
            new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                .setPRF(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))
                .setProvider("BC")
                .build(passwd));

        String old = setProperty(PBE_MAX_ITERATION_COUNT, "1");
        try
        {
            checkDecryptRejected(encInfo,
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd), "greater than 1");
        }
        finally
        {
            setProperty(PBE_MAX_ITERATION_COUNT, old);
        }
    }

    /**
     * With no override in place the built in bound must still reject an oversized count.
     */
    public void testPbkdf2IterationCountDefaultBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(10000001), null);

        String old = setProperty(PBE_MAX_ITERATION_COUNT, null);
        try
        {
            checkDecryptRejected(encInfo,
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd), "greater than 10000000");
        }
        finally
        {
            setProperty(PBE_MAX_ITERATION_COUNT, old);
        }
    }

    /**
     * The explicit-prf branch of the PBES2 decryptor must be bounded as well.
     */
    public void testPbkdf2IterationCountBoundWithPrf()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(10000001),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE));

        PBES2Parameters pbeParams = PBES2Parameters.getInstance(
            encInfo.toASN1Structure().getEncryptionAlgorithm().getParameters());
        assertFalse(PBKDF2Params.getInstance(pbeParams.getKeyDerivationFunc().getParameters()).isDefaultPrf());

        String old = setProperty(PBE_MAX_ITERATION_COUNT, null);
        try
        {
            checkDecryptRejected(encInfo,
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd), "greater than 10000000");
        }
        finally
        {
            setProperty(PBE_MAX_ITERATION_COUNT, old);
        }
    }

    /**
     * A count that does not even fit in an int must be rejected rather than silently truncated.
     */
    public void testPbkdf2OversizedIterationCount()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(BigInteger.valueOf(2).pow(40)), null);

        checkDecryptRejected(encInfo,
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd), "invalid iteration count");
    }

    /**
     * A count of 2^32 + 10000001 truncates to 10000001 when read with intValue(), so a bound
     * applied to the truncated int would be bypassed - the count has to be checked as it was
     * encoded.
     */
    public void testPbkdf2TruncatedIterationCount()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(),
            new ASN1Integer(BigInteger.valueOf(2).pow(32).add(BigInteger.valueOf(10000001))), null);

        checkDecryptRejected(encInfo,
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd), "invalid iteration count");
    }

    public void testPbkdf2NegativeIterationCount()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(BigInteger.valueOf(-1)), null);

        checkDecryptRejected(encInfo,
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd), "invalid iteration count");
    }

    /**
     * The OpenSSL flavoured PKCS#8 decryptor reads the same unauthenticated parameters, so it
     * carries the same bound.
     */
    public void testOpenSSLPbkdf2IterationCountBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = encryptPrivateKeyInfo();

        String old = setProperty(PBE_MAX_ITERATION_COUNT, "1");
        try
        {
            checkDecryptRejected(encInfo,
                new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd), "greater than 1");
        }
        finally
        {
            setProperty(PBE_MAX_ITERATION_COUNT, old);
        }
    }

    public void testOpenSSLPbkdf2IterationCountDefaultBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(10000001), null);

        String old = setProperty(PBE_MAX_ITERATION_COUNT, null);
        try
        {
            checkDecryptRejected(encInfo,
                new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd), "greater than 10000000");
        }
        finally
        {
            setProperty(PBE_MAX_ITERATION_COUNT, old);
        }
    }

    public void testOpenSSLPbkdf2OversizedIterationCount()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withKdfParams(
            encryptPrivateKeyInfo(), new ASN1Integer(BigInteger.valueOf(2).pow(40)), null);

        checkDecryptRejected(encInfo,
            new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd), "invalid iteration count");

        encInfo = withKdfParams(
            encryptPrivateKeyInfo(),
            new ASN1Integer(BigInteger.valueOf(2).pow(32).add(BigInteger.valueOf(10000001))), null);

        checkDecryptRejected(encInfo,
            new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd), "invalid iteration count");
    }

    /**
     * A modest scrypt cost must still round-trip - the scrypt bound may not break normal use.
     */
    public void testScryptRoundTrip()
        throws Exception
    {
        PBKDFConfig scrypt = new ScryptConfig.Builder(1024, 8, 1).withSaltLength(20).build();

        PKCS8EncryptedPrivateKeyInfo encInfo = new PKCS8EncryptedPrivateKeyInfoBuilder(scryptKey).build(
            new JcePKCSPBEOutputEncryptorBuilder(scrypt, NISTObjectIdentifiers.id_aes256_CBC)
                .setProvider("BC")
                .build("Rabbit".toCharArray()));

        PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray()));

        assertTrue(Arrays.areEqual(scryptKey, info.getEncoded()));
    }

    /**
     * The scrypt cost parameters travel in the same unauthenticated container: N = 2^24 with
     * r = 8 asks for 16 GiB of working memory and must be refused before the derivation runs.
     */
    public void testScryptCostBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withScryptParams(
            new PKCS8EncryptedPrivateKeyInfo(pkcs8Scrypt), BigInteger.valueOf(1 << 24), BigInteger.valueOf(8));

        String old = setProperty(PBE_MAX_SCRYPT_MEMORY, null);
        try
        {
            checkDecryptRejected(encInfo,
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray()),
                "scrypt cost parameters require more than 1073741824 bytes");
        }
        finally
        {
            setProperty(PBE_MAX_SCRYPT_MEMORY, old);
        }
    }

    /**
     * The memory ceiling is configurable: lowering it below the RFC 7914 vector's 1 GiB cost
     * must reject that vector before any memory is committed.
     */
    public void testScryptCostBoundOverride()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = new PKCS8EncryptedPrivateKeyInfo(pkcs8Scrypt);

        String old = setProperty(PBE_MAX_SCRYPT_MEMORY, "1048576");
        try
        {
            checkDecryptRejected(encInfo,
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray()),
                "scrypt cost parameters require more than 1048576 bytes");
        }
        finally
        {
            setProperty(PBE_MAX_SCRYPT_MEMORY, old);
        }
    }

    public void testScryptBlockSizeBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withScryptParams(
            new PKCS8EncryptedPrivateKeyInfo(pkcs8Scrypt), BigInteger.valueOf(2), BigInteger.valueOf(1025));

        checkDecryptRejected(encInfo,
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray()),
            "scrypt block size (1025) greater than 1024");
    }

    /**
     * Malformed scrypt parameters - including a cost of 2^32 + 1024 that would truncate to a
     * plausible 1024 through intValue() - are rejected before the derivation.
     */
    public void testScryptInvalidParameters()
        throws Exception
    {
        InputDecryptorProvider decryptorProvider =
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray());

        checkDecryptRejected(withScryptParams(
            new PKCS8EncryptedPrivateKeyInfo(pkcs8Scrypt), BigInteger.valueOf(0), BigInteger.valueOf(8)),
            decryptorProvider, "invalid scrypt parameters");

        checkDecryptRejected(withScryptParams(
            new PKCS8EncryptedPrivateKeyInfo(pkcs8Scrypt), BigInteger.valueOf(1024), BigInteger.valueOf(-1)),
            decryptorProvider, "invalid scrypt parameters");

        checkDecryptRejected(withScryptParams(
            new PKCS8EncryptedPrivateKeyInfo(pkcs8Scrypt), BigInteger.valueOf(2).pow(32).add(BigInteger.valueOf(1024)), BigInteger.valueOf(8)),
            decryptorProvider, "invalid scrypt parameters");
    }

    public void testScryptParallelizationBound()
        throws Exception
    {
        // scrypt also allocates ~128 * r * p bytes for its B array, so the parallelization
        // parameter p is held to the same memory budget as N. A genuine key with p exactly at
        // the bound (128 * r * p = 1 MiB) still decrypts, one byte less of budget refuses it.
        PKCS8EncryptedPrivateKeyInfo encInfo = new PKCS8EncryptedPrivateKeyInfoBuilder(scryptKey).build(
            new JcePKCSPBEOutputEncryptorBuilder(new ScryptConfig.Builder(16, 8, 1024).withSaltLength(20).build(), NISTObjectIdentifiers.id_aes256_CBC)
                .setProvider("BC")
                .build("Rabbit".toCharArray()));

        String old = setProperty(PBE_MAX_SCRYPT_MEMORY, String.valueOf(1024 * 1024));
        try
        {
            PrivateKeyInfo pkInfo = encInfo.decryptPrivateKeyInfo(
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray()));

            assertTrue("scrypt key round trip failed", Arrays.areEqual(scryptKey, pkInfo.getEncoded()));

            setProperty(PBE_MAX_SCRYPT_MEMORY, String.valueOf(1024 * 1024 - 1));

            checkDecryptRejected(encInfo,
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray()),
                "scrypt cost parameters require more than 1048575 bytes");
        }
        finally
        {
            setProperty(PBE_MAX_SCRYPT_MEMORY, old);
        }
    }

    public void testScryptParallelizationEngineCeiling()
        throws Exception
    {
        // attacker-crafted scrypt parameters: tiny N, but p at the engine's ceiling for r = 1
        // (Integer.MAX_VALUE / 1024), which needs 128 * r * p = 256 MiB for the B array alone.
        // With a 64 MiB budget this has to be refused before any allocation is attempted.
        PKCS8EncryptedPrivateKeyInfo encInfo = withScryptParams(
            new PKCS8EncryptedPrivateKeyInfo(pkcs8Scrypt), BigInteger.valueOf(2), BigInteger.ONE,
            BigInteger.valueOf(Integer.MAX_VALUE / 1024));

        String old = setProperty(PBE_MAX_SCRYPT_MEMORY, String.valueOf(64 * 1024 * 1024));
        try
        {
            checkDecryptRejected(encInfo,
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray()),
                "scrypt cost parameters require more than 67108864 bytes");
        }
        finally
        {
            setProperty(PBE_MAX_SCRYPT_MEMORY, old);
        }
    }

    public void testScryptParallelizationInvalid()
        throws Exception
    {
        // a non-positive p, or one that does not fit in an int (and so would be silently
        // truncated by intValue()), must be rejected outright.
        BigInteger[] hostile = { BigInteger.ZERO, BigInteger.valueOf(-1), BigInteger.ONE.shiftLeft(32).add(BigInteger.ONE) };

        for (int i = 0; i != hostile.length; i++)
        {
            checkDecryptRejected(withScryptParams(
                new PKCS8EncryptedPrivateKeyInfo(pkcs8Scrypt), BigInteger.valueOf(2), BigInteger.ONE, hostile[i]),
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build("Rabbit".toCharArray()),
                "invalid scrypt parameters");
        }
    }

    /**
     * The PKCS#12-PBE branch of both PKCS#8 decryptors, and the lightweight PKCS#12-PBE
     * decryptor, read the iteration count from the same unauthenticated AlgorithmIdentifier.
     */
    public void testPKCS12PbeIterationCountBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = encryptPKCS12PbePrivateKeyInfo();

        assertTrue(Arrays.areEqual(pkInfo, encInfo.decryptPrivateKeyInfo(
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd)).getEncoded()));
        assertTrue(Arrays.areEqual(pkInfo, encInfo.decryptPrivateKeyInfo(
            new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd)).getEncoded()));
        assertTrue(Arrays.areEqual(pkInfo, encInfo.decryptPrivateKeyInfo(
            new BcPKCS12PBEInputDecryptorProviderBuilder().build(passwd)).getEncoded()));

        String old = setProperty(PBE_MAX_ITERATION_COUNT, "1");
        try
        {
            checkDecryptRejected(encInfo,
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd), "greater than 1");
            checkDecryptRejected(encInfo,
                new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd), "greater than 1");
        }
        finally
        {
            setProperty(PBE_MAX_ITERATION_COUNT, old);
        }

        old = setProperty(PKCS12_MAX_IT_COUNT, "1");
        try
        {
            checkDecryptRejected(encInfo,
                new BcPKCS12PBEInputDecryptorProviderBuilder().build(passwd), "greater than 1");
        }
        finally
        {
            setProperty(PKCS12_MAX_IT_COUNT, old);
        }
    }

    public void testPKCS12PbeIterationCountDefaultBound()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withPbeIterationCount(
            encryptPKCS12PbePrivateKeyInfo(), new ASN1Integer(10000001));

        String oldPbe = setProperty(PBE_MAX_ITERATION_COUNT, null);
        String oldPkcs12 = setProperty(PKCS12_MAX_IT_COUNT, null);
        try
        {
            checkDecryptRejected(encInfo,
                new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd), "greater than 10000000");
            checkDecryptRejected(encInfo,
                new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd), "greater than 10000000");
            checkDecryptRejected(encInfo,
                new BcPKCS12PBEInputDecryptorProviderBuilder().build(passwd), "greater than 5000000");
        }
        finally
        {
            setProperty(PBE_MAX_ITERATION_COUNT, oldPbe);
            setProperty(PKCS12_MAX_IT_COUNT, oldPkcs12);
        }
    }

    /**
     * 2^32 + 1024 truncates to the writer's genuine count of 1024 through intValue(), so an
     * unchecked decryptor would happily decrypt the key - the count must be checked as encoded.
     */
    public void testPKCS12PbeOversizedIterationCount()
        throws Exception
    {
        PKCS8EncryptedPrivateKeyInfo encInfo = withPbeIterationCount(
            encryptPKCS12PbePrivateKeyInfo(),
            new ASN1Integer(BigInteger.valueOf(2).pow(32).add(BigInteger.valueOf(1024))));

        checkDecryptRejected(encInfo,
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd), "invalid iteration count");
        checkDecryptRejected(encInfo,
            new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd), "invalid iteration count");
        checkDecryptRejected(encInfo,
            new BcPKCS12PBEInputDecryptorProviderBuilder().build(passwd), "iteration counts >= 2^31 are not supported");

        encInfo = withPbeIterationCount(encryptPKCS12PbePrivateKeyInfo(), new ASN1Integer(BigInteger.valueOf(-1)));

        checkDecryptRejected(encInfo,
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(passwd), "invalid iteration count");
        checkDecryptRejected(encInfo,
            new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passwd), "invalid iteration count");
        checkDecryptRejected(encInfo,
            new BcPKCS12PBEInputDecryptorProviderBuilder().build(passwd), "negative iteration count found");
    }

    /**
     * Set (or, for a null value, clear) a system property, returning its previous value.
     */
    private static String setProperty(String name, String value)
    {
        String old = System.getProperty(name);

        if (value == null)
        {
            System.clearProperty(name);
        }
        else
        {
            System.setProperty(name, value);
        }

        return old;
    }

    private static int getJvmVersion()
    {
        String version = System.getProperty("java.version");

        if (version.startsWith("1.7"))
        {
            return 7;
        }
        if (version.startsWith("1.8"))
        {
            return 8;
        }
        if (version.startsWith("1.9"))
        {
            return 9;
        }
        if (version.startsWith("1.1"))
        {
            return 10;
        }

        return -1;
    }
}
