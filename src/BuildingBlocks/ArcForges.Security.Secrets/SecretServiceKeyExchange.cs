// SPDX-License-Identifier: AGPL-3.0-only
using System.Numerics;
using System.Security.Cryptography;

namespace ArcForges.Security.Secrets;

/// <summary>
/// The Secret Service transport encryption <c>dh-ietf1024-sha256-aes128-cbc-pkcs7</c>: Diffie-Hellman over the RFC 2409 second
/// Oakley group (1024-bit MODP, generator 2), the shared secret left-padded to 128 bytes, HKDF-SHA256 with no salt and no info to a
/// 16-byte AES key, then AES-128-CBC with PKCS#7 padding and a random 16-byte IV per value. It protects the value on the bus; it does
/// not authenticate the service, which is whoever owns <c>org.freedesktop.secrets</c> on the user's own bus.
/// </summary>
internal sealed class SecretServiceKeyExchange : IDisposable
{
    internal const string Algorithm = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
    internal const int KeyBytes = 16;
    private const int PrimeBytes = 128;
    private static readonly BigInteger Prime = new(Convert.FromHexString(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"), isUnsigned: true, isBigEndian: true);

    private static readonly BigInteger Generator = new(2);
    private BigInteger _private;

    public SecretServiceKeyExchange()
    {
        byte[] random = RandomNumberGenerator.GetBytes(PrimeBytes);
        try
        {
            // An exponent in [2, p - 2].
            _private = (new BigInteger(random, isUnsigned: true, isBigEndian: true) % (Prime - 3)) + 2;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }

        PublicKey = BigInteger.ModPow(Generator, _private, Prime).ToByteArray(isUnsigned: true, isBigEndian: true);
    }

    /// <summary>The unsigned big-endian public value sent with <c>OpenSession</c>.</summary>
    public byte[] PublicKey { get; }

    /// <summary>Derives the session's AES-128 key from the service's public value.</summary>
    public byte[] DeriveKey(byte[] peerPublicKey)
    {
        ArgumentNullException.ThrowIfNull(peerPublicKey);
        if (peerPublicKey.Length is 0 or > PrimeBytes)
        {
            throw new InvalidDataException("The Secret Service returned a public value of an invalid size.");
        }

        var peer = new BigInteger(peerPublicKey, isUnsigned: true, isBigEndian: true);
        if (peer <= BigInteger.One || peer >= Prime - BigInteger.One)
        {
            throw new InvalidDataException("The Secret Service returned an invalid public value.");
        }

        byte[] shared = BigInteger.ModPow(peer, _private, Prime).ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] padded = new byte[PrimeBytes];
        try
        {
            shared.CopyTo(padded, PrimeBytes - shared.Length);
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, padded, KeyBytes, salt: [], info: []);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
            CryptographicOperations.ZeroMemory(padded);
        }
    }

    public void Dispose() => _private = BigInteger.Zero;
}
