using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace JwtLearningDemo;

/// <summary>
/// Simulates the asymmetric RSA key separation between:
/// 1. The Auth Server (which holds PrivateSigningKey to sign tokens with RS256)
/// 2. Your API Endpoint (which ONLY holds PublicValidationKey to verify tokens)
/// </summary>
public static class JwtSettings
{
    public const string Issuer = "https://jwt-learning-demo.local";
    public const string Audience = "jwt-learning-demo-api";

    // Toggle whether service tokens without an 'exp' claim are accepted
    public const bool AllowServiceTokenWithoutExpiry = true;

    // Generate a 2048-bit RSA key pair on startup for the demo
    private static readonly RSA FullRsaKeyPair = RSA.Create(2048);

    /// <summary>
    /// AUTH SERVER ONLY: Contains BOTH Private and Public RSA parameters.
    /// Used in AuthController to sign JWT tokens with RS256.
    /// </summary>
    public static RsaSecurityKey AuthServerPrivateKey { get; } =
        new RsaSecurityKey(FullRsaKeyPair.ExportParameters(includePrivateParameters: true))
        {
            KeyId = "demo-rsa-key-1"
        };

    /// <summary>
    /// YOUR API ENDPOINT ONLY: Contains ONLY the Public RSA parameters (Modulus + Exponent).
    /// Used in Program.cs TokenValidationParameters.IssuerSigningKey.
    /// Cannot be used to sign/forge tokens!
    /// </summary>
    public static RsaSecurityKey ApiEndpointPublicKey { get; } =
        new RsaSecurityKey(FullRsaKeyPair.ExportParameters(includePrivateParameters: false))
        {
            KeyId = "demo-rsa-key-1"
        };

    /// <summary>
    /// Exports the Public Key in standard PEM format so you can see what your API receives.
    /// </summary>
    public static string GetPublicKeyPem() => FullRsaKeyPair.ExportSubjectPublicKeyInfoPem();
}
