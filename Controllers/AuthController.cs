using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtLearningDemo.Controllers;

/// <summary>
/// Simulates the Auth Server / Identity Provider.
/// Uses the RSA PRIVATE KEY (JwtSettings.AuthServerPrivateKey) + RS256 to sign tokens.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[AllowAnonymous]
public class AuthController : ControllerBase
{
    /// <summary>
    /// 1. Generate a standard user or admin JWT token signed with the RSA PRIVATE KEY (RS256).
    /// </summary>
    [HttpPost("token")]
    public IActionResult GenerateStandardToken(
        [FromQuery] string username = "alice",
        [FromQuery] string role = "User",
        [FromQuery] int expiresInMinutes = 5)
    {
        var utcNow = DateTime.UtcNow;

        // STEP 1: Define the Claims (stored inside the JWT Payload)
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, username),
            new(ClaimTypes.Name, username),
            new(ClaimTypes.Role, role),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("token_type", "user")
        };

        // STEP 2: Sign using the Auth Server's RSA PRIVATE KEY + RS256 algorithm
        var credentials = new SigningCredentials(
            JwtSettings.AuthServerPrivateKey,
            SecurityAlgorithms.RsaSha256);

        // STEP 3: Build the JwtSecurityToken (Header + Payload + Signature metadata)
        var jwtToken = new JwtSecurityToken(
            issuer: JwtSettings.Issuer,
            audience: JwtSettings.Audience,
            claims: claims,
            notBefore: utcNow,
            expires: utcNow.AddMinutes(expiresInMinutes),
            signingCredentials: credentials);

        // STEP 4: Serialize to compact JWT format: Base64Url(Header).Base64Url(Payload).Base64Url(Signature)
        var tokenString = new JwtSecurityTokenHandler().WriteToken(jwtToken);

        return Ok(new
        {
            Scenario = $"RS256 token signed with RSA PRIVATE KEY for '{username}' (role '{role}', valid {expiresInMinutes} min)",
            Algorithm = SecurityAlgorithms.RsaSha256,
            KeyId = JwtSettings.AuthServerPrivateKey.KeyId,
            Token = tokenString,
            NotBeforeUtc = utcNow,
            ExpiresUtc = utcNow.AddMinutes(expiresInMinutes)
        });
    }

    /// <summary>
    /// 2. Generate a Service Token WITHOUT an 'exp' (expiration) claim, signed with the RSA PRIVATE KEY.
    /// Demonstrates your custom ValidateTokenLifetime allowing service tokens without expiry!
    /// </summary>
    [HttpPost("service-token-no-expiry")]
    public IActionResult GenerateServiceTokenWithoutExpiry(
        [FromQuery] string serviceName = "billing-worker",
        [FromQuery] int notBeforeOffsetMinutes = 0)
    {
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(notBeforeOffsetMinutes);

        var credentials = new SigningCredentials(
            JwtSettings.AuthServerPrivateKey,
            SecurityAlgorithms.RsaSha256);

        var header = new JwtHeader(credentials);

        // Notice: We intentionally do NOT set 'exp' (expires) in this payload!
        var payload = new JwtPayload
        {
            { JwtRegisteredClaimNames.Iss, JwtSettings.Issuer },
            { JwtRegisteredClaimNames.Aud, JwtSettings.Audience },
            { JwtRegisteredClaimNames.Sub, serviceName },
            { ClaimTypes.Name, serviceName },
            { ClaimTypes.Role, "Admin" },
            { "token_type", "service" }, // Checked by IsServiceToken(securityToken)
            { JwtRegisteredClaimNames.Nbf, notBefore.ToUnixTimeSeconds() }
        };

        var secToken = new JwtSecurityToken(header, payload);
        var tokenString = new JwtSecurityTokenHandler().WriteToken(secToken);

        return Ok(new
        {
            Scenario = notBeforeOffsetMinutes > 0
                ? $"RS256 Service token WITHOUT 'exp', but 'nbf' is {notBeforeOffsetMinutes} min in the future (will return 401!)"
                : "RS256 Service token WITHOUT 'exp' (will be ACCEPTED by custom ValidateTokenLifetime!)",
            Algorithm = SecurityAlgorithms.RsaSha256,
            Token = tokenString,
            NotBeforeUtc = notBefore.UtcDateTime,
            ExpiresUtc = (DateTime?)null
        });
    }

    /// <summary>
    /// 3. Generate an already-expired RS256 token so you can test 401 Unauthorized.
    /// </summary>
    [HttpPost("expired-token")]
    public IActionResult GenerateExpiredToken([FromQuery] string username = "alice")
    {
        var utcNow = DateTime.UtcNow;
        var credentials = new SigningCredentials(
            JwtSettings.AuthServerPrivateKey,
            SecurityAlgorithms.RsaSha256);

        var jwtToken = new JwtSecurityToken(
            issuer: JwtSettings.Issuer,
            audience: JwtSettings.Audience,
            claims: new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, "User"),
                new Claim("token_type", "user")
            },
            notBefore: utcNow.AddMinutes(-20),
            expires: utcNow.AddMinutes(-10), // Expired 10 minutes ago!
            signingCredentials: credentials);

        var tokenString = new JwtSecurityTokenHandler().WriteToken(jwtToken);

        return Ok(new
        {
            Scenario = "Expired RS256 token (expired 10 minutes ago -> calling protected endpoints will return 401 Unauthorized)",
            Algorithm = SecurityAlgorithms.RsaSha256,
            Token = tokenString,
            NotBeforeUtc = utcNow.AddMinutes(-20),
            ExpiresUtc = utcNow.AddMinutes(-10)
        });
    }

    /// <summary>
    /// 4. View the RSA Public Key that your API Endpoint uses to verify signatures.
    /// (Similar to an Auth Server's /.well-known/jwks.json endpoint)
    /// </summary>
    [HttpGet("public-key")]
    public IActionResult GetPublicKey()
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(JwtSettings.ApiEndpointPublicKey);
        return Ok(new
        {
            Description = "This is the RSA PUBLIC KEY configured on Program.cs (IssuerSigningKey). It can verify RS256 tokens, but cannot sign new tokens.",
            KeyId = JwtSettings.ApiEndpointPublicKey.KeyId,
            HasPrivateKey = JwtSettings.ApiEndpointPublicKey.PrivateKeyStatus,
            PublicKeyPem = JwtSettings.GetPublicKeyPem(),
            JsonWebKey = new
            {
                jwk.Kty,
                jwk.Kid,
                Alg = SecurityAlgorithms.RsaSha256,
                jwk.N,
                jwk.E
            }
        });
    }

    /// <summary>
    /// 5. Inspect/decode any JWT token string without validating its signature or lifetime,
    /// so you can see the raw Header (alg: RS256, kid: demo-rsa-key-1) and Payload claims.
    /// </summary>
    [HttpGet("inspect")]
    public IActionResult InspectToken([FromQuery] string token)
    {
        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(token))
            return BadRequest("Not a valid JWT format (expected Header.Payload.Signature).");

        var jwt = handler.ReadJwtToken(token);
        return Ok(new
        {
            Header = jwt.Header,
            Payload = jwt.Payload,
            ValidFromUtc = jwt.ValidFrom == DateTime.MinValue ? (DateTime?)null : jwt.ValidFrom,
            ValidToUtc = jwt.ValidTo == DateTime.MinValue ? (DateTime?)null : jwt.ValidTo
        });
    }
}
