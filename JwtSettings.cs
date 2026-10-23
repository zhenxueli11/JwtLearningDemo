namespace JwtLearningDemo;

/// <summary>
/// Demo settings shared between token generation (AuthController)
/// and token validation (Program.cs).
/// In production, read these from appsettings.json / KeyVault.
/// </summary>
public static class JwtSettings
{
    public const string Issuer = "https://jwt-learning-demo.local";
    public const string Audience = "jwt-learning-demo-api";

    // Must be at least 256 bits (32 bytes) for HMAC-SHA256 (HS256)
    public const string SecretKey = "SuperSecretDemoKey_MustBeAtLeast32BytesLong!!";

    // Toggle whether service tokens without an 'exp' claim are accepted
    public const bool AllowServiceTokenWithoutExpiry = true;
}
