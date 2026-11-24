package org.bouncycastle.cms.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

import javax.crypto.SecretKey;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTagLengthException;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.bc.BcKEKEnvelopedRecipient;
import org.bouncycastle.cms.bc.BcPasswordEnvelopedRecipient;
import org.bouncycastle.cms.bc.BcRSAKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKTSKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.bc.BcAESSymmetricKeyUnwrapper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

public class AuthEnvelopedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String _signDN;
    private static KeyPair _signKP;
    private static X509Certificate _signCert;

    private static String _origDN;
    private static KeyPair _origKP;
    private static X509Certificate _origCert;

    private static String _reciDN;
    private static KeyPair _reciKP;
    private static X509Certificate _reciCert;

    private static KeyPair _origEcKP;
    private static KeyPair _reciEcKP;
    private static X509Certificate _reciEcCert;

    private static boolean _initialised = false;

    public boolean DEBUG = true;

    private static final byte[] Sample1 = Base64.decode("MIAGCyqGSIb3DQEJEAEXoIAwgAIBADGBmzCBmAIBAoABATANBgkqhkiG9w0BAQEFAASBgG9yJPC3zFmIbPTtSrrTD+71lluua3F1" +
        "/V/XzzDOczjdymy4tI4sle5HSxJN8yrw+m2JdWKb4s/u4frvmNqE6fcqfFtLpLEMXJneoEWWXZFKbndoqQNRMgfKGCncpeWhktRc" +
        "SRtbEEk/H4hWggJGmVClS7f/nmCDjwyANBnI3shYMIAGCSqGSIb3DQEHATAfBglghkgBZQMEAQYwEgQQLO0PwnuhYXRk8pLLhgik" +
        "0aCABB8KvxIkbmBKT73Oz4xtf0DNNGmdn+tzPcOldJUQWCEnAAAAAAQMn+tzPcOldJUQWCEnAAAAAAAA");

    private static final byte[] Sample1Key = Base64.decode("MIICdAIBADANBgkqhkiG9w0BAQEFAASCAl4wggJaAgEAAoGBAMtFuFyzl4jgeuPL\n" +
        "uGp8Niqf11QGWVDTpZvE7VabLoPanzuVgjTYC8oJOq4PvVYW5V56KeGzXhsnhsDt\n" +
        "IBaRESTFuXM50uiH4mRPGsqCFJvbmokvxfhb24TPg3gQ5E2SEvmXFN425J/jvcqq\n" +
        "XpX7wQGtr9DWLIXsqPeLKhoy/qdhAgMBAAECf3xBB80spVPEggTXW2aoebwXt1pw\n" +
        "8BqzUnSWqlZaHJGdtgbxL0qNsjECX42Djj+1vzddJud0dRHvu4m8y8zlVl/Ro+fv\n" +
        "xETE9nCKzt1MlaNUG9mywZeWLjyOKZFY5fxc+yzoH+d8fcXTM7SwKG9bl6hisU0j\n" +
        "LWdramL5eV/kILECQQDxD5WuYZY2gF2DhtqAxCaf2MLgDlXzj1PcX3X1nPlrNKy3\n" +
        "G0jyMWofmZFORzUz1G0Dlyfxk3Wlc+1IIWbxH5dNAkEA196fcWJN9ZpavkuLKG3W\n" +
        "5sSWAs05Jdk2FGw/pbycoIaMOtf/3KeWJTSNxK1jKsoTQN3RUF9h2jtFhf+yqOjO\n" +
        "ZQJAGpf7jVdauPyEVIRGCrqZAD1rkkhClzISsFcfrk74/Si8fR7Xd1CYQpAwhZA5\n" +
        "gFRJCoJcd7wq2Gvnm3OD5cn0aQJAP98H8CV1CaltFgcGGqU9Q7SA6j1Mnm1BehN5\n" +
        "VZGUCk8lKLgGZYRUgZemJr5irCN0ROoc55oBOu/0pyw78YxInQJBAKjibmupsLLt\n" +
        "kUQF7vyalONmkebwEDwTHODWOGXC7xmcvXhFAnlpYkv3QCohF53X0RS+VprfojbI\n" +
        "X0T/eAP0zJA=");

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            Security.addProvider(new BouncyCastleProvider());

            _signDN = "O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _origEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);
        }
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    public AuthEnvelopedDataTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(AuthEnvelopedDataTest.class);
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(AuthEnvelopedDataTest.class));
    }

    public void testKeyTransMinimumTagSize()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");

        // generate AuthEnvelopedData with a 96-bit (12-octet) GCM tag - valid under RFC 5084
        OutputAEADEncryptor enc = createAEADEncryptor(NISTObjectIdentifiers.id_aes128_GCM, 96);

        assertEquals(12, GCMParameters.getInstance(enc.getAlgorithmIdentifier().getParameters()).getIcvLen());

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), enc);

        // a minimum at or below the actual tag size recovers as normal
        RecipientInformation recipient = firstRecipient(authData);
        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate())
            .setProvider(BC).setMinimumTagSize(96));
        assertEquals("Hello, world!", Strings.fromByteArray(recData));

        // a minimum above the actual tag size is refused with CMSTagLengthException
        try
        {
            recipient = firstRecipient(authData);
            recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate())
                .setProvider(BC).setMinimumTagSize(128));

            fail("content recovered under a tag shorter than the configured minimum");
        }
        catch (CMSTagLengthException e)
        {
            // expected
        }

        // a full (128-bit) tag satisfies a 128-bit minimum
        CMSAuthEnvelopedDataGenerator fullGen = new CMSAuthEnvelopedDataGenerator();
        fullGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
        CMSAuthEnvelopedData fullData = fullGen.generate(new CMSProcessableByteArray(message),
            createAEADEncryptor(NISTObjectIdentifiers.id_aes128_GCM, 128));

        recipient = firstRecipient(fullData);
        byte[] fullRec = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate())
            .setProvider(BC).setMinimumTagSize(128));
        assertEquals("Hello, world!", Strings.fromByteArray(fullRec));
    }

    public void testMinimumTagSizeOtherRecipients()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");
        SecretKey kek = CMSTestUtil.makeAESKey(128);
        char[] password = "password".toCharArray();

        // KEK recipient, downgraded 64-bit GCM tag
        CMSAuthEnvelopedData authData = generateShortTagData(NISTObjectIdentifiers.id_aes128_GCM,
            new JceKEKRecipientInfoGenerator(new byte[]{ 1, 2, 3, 4, 5 }, kek).setProvider(BC), message);

        assertEquals("KEK recipient", "Hello, world!", Strings.fromByteArray(firstRecipient(authData).getContent(
            new JceKEKEnvelopedRecipient(kek).setProvider(BC).setMinimumTagSize(64))));
        confirmTagSizeRefused("KEK recipient", authData,
            new JceKEKEnvelopedRecipient(kek).setProvider(BC).setMinimumTagSize(128));
        confirmTagSizeRefused("Bc KEK recipient", authData,
            new BcKEKEnvelopedRecipient(new BcAESSymmetricKeyUnwrapper(new KeyParameter(kek.getEncoded())))
            {
                {
                    setMinimumTagSizeInBits(128);
                }
            });

        // password recipient, downgraded 64-bit GCM tag
        authData = generateShortTagData(NISTObjectIdentifiers.id_aes128_GCM,
            new JcePasswordRecipientInfoGenerator(CMSAlgorithm.AES128_CBC, password).setProvider(BC), message);

        assertEquals("password recipient", "Hello, world!", Strings.fromByteArray(firstRecipient(authData).getContent(
            new JcePasswordEnvelopedRecipient(password).setProvider(BC).setMinimumTagSize(64))));
        confirmTagSizeRefused("password recipient", authData,
            new JcePasswordEnvelopedRecipient(password).setProvider(BC).setMinimumTagSize(128));
        confirmTagSizeRefused("Bc password recipient", authData,
            new BcPasswordEnvelopedRecipient(password)
            {
                {
                    setMinimumTagSizeInBits(128);
                }
            });

        // key agreement recipient, downgraded 64-bit GCM tag
        authData = generateShortTagData(NISTObjectIdentifiers.id_aes128_GCM,
            new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(),
                CMSAlgorithm.AES128_WRAP).addRecipient(_reciEcCert).setProvider(BC), message);

        assertEquals("key agree recipient", "Hello, world!", Strings.fromByteArray(firstRecipient(authData).getContent(
            new JceKeyAgreeEnvelopedRecipient(_reciEcKP.getPrivate()).setProvider(BC).setMinimumTagSize(64))));
        confirmTagSizeRefused("key agree recipient", authData,
            new JceKeyAgreeEnvelopedRecipient(_reciEcKP.getPrivate()).setProvider(BC).setMinimumTagSize(128));

        // key transport recipients, downgraded 64-bit GCM tag
        authData = generateShortTagData(NISTObjectIdentifiers.id_aes128_GCM,
            new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC), message);

        assertEquals("key trans recipient", "Hello, world!", Strings.fromByteArray(firstRecipient(authData).getContent(
            new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC).setMinimumTagSize(64))));
        confirmTagSizeRefused("key trans recipient", authData,
            new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC).setMinimumTagSize(128));
        confirmTagSizeRefused("KTS key trans recipient", authData,
            new JceKTSKeyTransEnvelopedRecipient(_reciKP.getPrivate(), new JceKeyTransRecipientId(_reciCert))
                .setProvider(BC).setMinimumTagSize(128));
        confirmTagSizeRefused("Bc key trans recipient", authData,
            new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(_reciKP.getPrivate().getEncoded()))
            {
                {
                    setMinimumTagSizeInBits(128);
                }
            });

        // key transport recipient, downgraded 64-bit CCM tag
        authData = generateShortTagData(NISTObjectIdentifiers.id_aes128_CCM,
            new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC), message);

        confirmTagSizeRefused("CCM key trans recipient", authData,
            new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC).setMinimumTagSize(128));
    }

    public void testTruncatedTagDowngrade()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");

        // a legitimate sender protects the content with a full 128-bit GCM tag
        byte[] encoded = encodeAuthEnvelopedData(message,
            new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC),
            createAEADEncryptor(NISTObjectIdentifiers.id_aes128_GCM, 128));

        // an attacker holding no key material cuts the tag down to 32 bits and rewrites the ICV length -
        // a GCM tag is a prefix of the full tag, so the message still authenticates under the shorter tag.
        byte[] downgraded = truncateGCMTag(encoded, 4);

        // with no minimum configured the recipient accepts the 32-bit tag
        assertEquals("Hello, world!", Strings.fromByteArray(firstRecipient(downgraded).getContent(
            new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC))));

        // with a minimum configured the downgraded message is refused
        try
        {
            firstRecipient(downgraded).getContent(
                new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC).setMinimumTagSize(128));

            fail("content recovered under a truncated tag");
        }
        catch (CMSTagLengthException e)
        {
            assertTrue("unexpected message " + e.getMessage(), e.getMessage().indexOf("32 bits") >= 0);
        }

        // AEAD parameters that cannot be read are refused rather than ignored when a minimum is set
        try
        {
            firstRecipient(replaceContentAlgorithm(encoded, new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_GCM)))
                .getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC).setMinimumTagSize(128));

            fail("content recovered with unreadable AEAD parameters");
        }
        catch (CMSTagLengthException e)
        {
            assertTrue("unexpected message " + e.getMessage(), e.getMessage().indexOf("tag size 0 bits") >= 0);
        }

        // the untouched message still recovers under the same minimum
        assertEquals("Hello, world!", Strings.fromByteArray(firstRecipient(encoded).getContent(
            new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC).setMinimumTagSize(128))));
    }

    private static CMSAuthEnvelopedData generateShortTagData(ASN1ObjectIdentifier contentAlgorithm,
        RecipientInfoGenerator recipientGen, byte[] message)
        throws Exception
    {
        OutputAEADEncryptor enc = createAEADEncryptor(contentAlgorithm, 64);

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(recipientGen);

        return authGen.generate(new CMSProcessableByteArray(message), enc);
    }

    /**
     * Produce the DER/BER encoding of an AuthEnvelopedData message laid out as CMSAuthEnvelopedDataGenerator
     * lays it out (CMSAuthEnvelopedData offers no encoding accessor in this version).
     */
    private static byte[] encodeAuthEnvelopedData(byte[] message, RecipientInfoGenerator recipientGen, OutputAEADEncryptor enc)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream cOut = enc.getOutputStream(bOut);

        cOut.write(message);
        cOut.close();

        EncryptedContentInfo eci = new EncryptedContentInfo(CMSObjectIdentifiers.data, enc.getAlgorithmIdentifier(),
            new BEROctetString(bOut.toByteArray()));

        return new ContentInfo(CMSObjectIdentifiers.authEnvelopedData, new AuthEnvelopedData(null,
            new DERSet(recipientGen.generate(enc.getKey())), eci, null, new DEROctetString(enc.getMAC()), null)).getEncoded();
    }

    /**
     * Build an AES-128 GCM or CCM content encryptor producing a tag of tagSizeInBits - the JCE content
     * encryptor builder in this version does not provide an OutputAEADEncryptor.
     */
    private static OutputAEADEncryptor createAEADEncryptor(ASN1ObjectIdentifier contentAlgorithm, int tagSizeInBits)
    {
        SecureRandom random = new SecureRandom();
        final byte[] key = new byte[16];
        byte[] nonce = new byte[12];

        random.nextBytes(key);
        random.nextBytes(nonce);

        final AEADBlockCipher cipher;
        final AlgorithmIdentifier algId;

        if (NISTObjectIdentifiers.id_aes128_CCM.equals(contentAlgorithm))
        {
            cipher = new CCMBlockCipher(new AESEngine());
            algId = new AlgorithmIdentifier(contentAlgorithm, new CCMParameters(nonce, tagSizeInBits / 8));
        }
        else
        {
            cipher = new GCMBlockCipher(new AESEngine());
            algId = new AlgorithmIdentifier(contentAlgorithm, new GCMParameters(nonce, tagSizeInBits / 8));
        }

        cipher.init(true, new AEADParameters(new KeyParameter(key), tagSizeInBits, nonce));

        return new OutputAEADEncryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return algId;
            }

            public OutputStream getOutputStream(OutputStream dOut)
            {
                return new CipherOutputStream(dOut, cipher);
            }

            public GenericKey getKey()
            {
                return new GenericKey(algId, key);
            }

            public OutputStream getAADStream()
            {
                return new OutputStream()
                {
                    public void write(byte[] buf, int off, int len)
                        throws IOException
                    {
                        cipher.processAADBytes(buf, off, len);
                    }

                    public void write(int b)
                        throws IOException
                    {
                        cipher.processAADByte((byte)b);
                    }
                };
            }

            public byte[] getMAC()
            {
                return cipher.getMac();
            }
        };
    }

    private static byte[] truncateGCMTag(byte[] encoded, int icvLen)
        throws Exception
    {
        AuthEnvelopedData authEnv = AuthEnvelopedData.getInstance(ContentInfo.getInstance(encoded).getContent());
        EncryptedContentInfo eci = authEnv.getAuthEncryptedContentInfo();
        GCMParameters gcmParams = GCMParameters.getInstance(eci.getContentEncryptionAlgorithm().getParameters());

        // the tag travels at the end of the encrypted content as well as in the mac field
        byte[] encContent = eci.getEncryptedContent().getOctets();
        byte[] truncContent = Arrays.copyOfRange(encContent, 0, encContent.length - gcmParams.getIcvLen() + icvLen);
        byte[] truncMac = Arrays.copyOfRange(authEnv.getMac().getOctets(), 0, icvLen);

        EncryptedContentInfo forgedEci = new EncryptedContentInfo(eci.getContentType(),
            new AlgorithmIdentifier(eci.getContentEncryptionAlgorithm().getAlgorithm(), new GCMParameters(gcmParams.getNonce(), icvLen)),
            new BEROctetString(truncContent));

        return new ContentInfo(CMSObjectIdentifiers.authEnvelopedData, new AuthEnvelopedData(authEnv.getOriginatorInfo(),
            authEnv.getRecipientInfos(), forgedEci, authEnv.getAuthAttrs(), new DEROctetString(truncMac), authEnv.getUnauthAttrs())).getEncoded();
    }

    private static byte[] replaceContentAlgorithm(byte[] encoded, AlgorithmIdentifier contentAlgorithm)
        throws Exception
    {
        AuthEnvelopedData authEnv = AuthEnvelopedData.getInstance(ContentInfo.getInstance(encoded).getContent());
        EncryptedContentInfo eci = authEnv.getAuthEncryptedContentInfo();

        EncryptedContentInfo forgedEci = new EncryptedContentInfo(eci.getContentType(), contentAlgorithm, eci.getEncryptedContent());

        return new ContentInfo(CMSObjectIdentifiers.authEnvelopedData, new AuthEnvelopedData(authEnv.getOriginatorInfo(),
            authEnv.getRecipientInfos(), forgedEci, authEnv.getAuthAttrs(), authEnv.getMac(), authEnv.getUnauthAttrs())).getEncoded();
    }

    private static RecipientInformation firstRecipient(byte[] encoded)
        throws Exception
    {
        return firstRecipient(new CMSAuthEnvelopedData(encoded));
    }

    private static RecipientInformation firstRecipient(CMSAuthEnvelopedData authData)
    {
        return (RecipientInformation)authData.getRecipientInfos().getRecipients().iterator().next();
    }

    private static void confirmTagSizeRefused(String label, CMSAuthEnvelopedData authData, Recipient recipient)
        throws Exception
    {
        try
        {
            firstRecipient(authData).getContent(recipient);

            fail(label + ": content recovered under a tag shorter than the configured minimum");
        }
        catch (CMSTagLengthException e)
        {
            assertTrue(label + ": unexpected message " + e.getMessage(), e.getMessage().indexOf("64 bits") >= 0);
        }
    }

    public void testSample1()
        throws Exception
    {
        CMSAuthEnvelopedData authEnv = new CMSAuthEnvelopedData(Sample1);

        RecipientInformationStore recipients = authEnv.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(Sample1Key));

        byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

        assertEquals("auth-enveloped data", Strings.fromByteArray(recData));

        assertTrue(Arrays.areEqual(Sample1, authEnv.getEncoded()));
    }

    public void testAttributes()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new BcCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM).build();

        assertEquals(NISTObjectIdentifiers.id_aes128_GCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)candidate;

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

        authGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                 Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                     new DERSet(new Time(new Date())));
                 attrs.put(testAttr.getAttrType(), testAttr);
                 return new AttributeTable(attrs);
            }
        });

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));
        
        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }
}