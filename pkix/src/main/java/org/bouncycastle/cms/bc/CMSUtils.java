package org.bouncycastle.cms.bc;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSTagLengthException;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.operator.GenericKey;

class CMSUtils
{
    private static final Set gcmAlgs = new HashSet();
    private static final Set ccmAlgs = new HashSet();

    static
    {
        gcmAlgs.add(NISTObjectIdentifiers.id_aes128_GCM);
        gcmAlgs.add(NISTObjectIdentifiers.id_aes192_GCM);
        gcmAlgs.add(NISTObjectIdentifiers.id_aes256_GCM);

        ccmAlgs.add(NISTObjectIdentifiers.id_aes128_CCM);
        ccmAlgs.add(NISTObjectIdentifiers.id_aes192_CCM);
        ccmAlgs.add(NISTObjectIdentifiers.id_aes256_CCM);
    }

    static CipherParameters getBcKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof CipherParameters)
        {
            return (CipherParameters)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new KeyParameter((byte[])key.getRepresentation());
        }

        throw new IllegalArgumentException("unknown generic key type");
    }

    /**
     * Return the length, in octets, of the AEAD authentication tag (ICV) carried by a content-encryption
     * AlgorithmIdentifier.
     *
     * @param contentAlgorithm the content-encryption AlgorithmIdentifier.
     * @return the tag length in octets, 0 if the AEAD parameters cannot be interpreted, or -1 when the
     * algorithm is not recognised.
     */
    static int getAEADMacLength(AlgorithmIdentifier contentAlgorithm)
    {
        ASN1ObjectIdentifier algorithm = contentAlgorithm.getAlgorithm();

        try
        {
            if (gcmAlgs.contains(algorithm))
            {
                return Math.max(0, GCMParameters.getInstance(contentAlgorithm.getParameters()).getIcvLen());
            }
            if (ccmAlgs.contains(algorithm))
            {
                return Math.max(0, CCMParameters.getInstance(contentAlgorithm.getParameters()).getIcvLen());
            }
        }
        catch (RuntimeException e)
        {
            // malformed or absent AEAD parameters - report no usable tag so a minimum fails closed.
            return 0;
        }

        return -1;
    }

    /**
     * Refuse an AEAD content algorithm whose authentication tag is shorter than the configured
     * minimum. A no-op when no minimum is set or when the content algorithm is not AEAD.
     *
     * @param minimumTagSizeInBits the minimum acceptable tag size in bits, 0 or less for no minimum.
     * @param contentAlgorithm the content-encryption AlgorithmIdentifier (carries the AEAD ICV length).
     * @throws CMSTagLengthException if the tag size is below the configured minimum.
     */
    static void checkTagSize(int minimumTagSizeInBits, AlgorithmIdentifier contentAlgorithm)
        throws CMSTagLengthException
    {
        if (minimumTagSizeInBits > 0)
        {
            int macLenOctets = getAEADMacLength(contentAlgorithm);

            if (macLenOctets >= 0 && (long)macLenOctets * 8 < minimumTagSizeInBits)
            {
                throw new CMSTagLengthException("AEAD tag size " + ((long)macLenOctets * 8)
                    + " bits below required minimum " + minimumTagSizeInBits + " bits");
            }
        }
    }
}
