using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtLearningDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
[AllowAnonymous]
public class AuthController : ControllerBase
{
    /// <summary>
    /// 1. Generate a standard user or admin JWT token (with 'nbf' and 'exp').
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

        // STEP 2: Create the SigningCredentials using our secret key + HMAC-SHA256
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSettings.SecretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

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
            Scenario = $"Standard token for '{username}' with role '{role}' (valid for {expiresInMinutes} min)",
            Token = tokenString,
            NotBeforeUtc = utcNow,
            ExpiresUtc = utcNow.AddMinutes(expiresInMinutes)
        });
    }

    /// <summary>
    /// 2. Generate a Service Token WITHOUT an 'exp' (expiration) claim.
    /// Demonstrates your custom ValidateTokenLifetime allowing service tokens without expiry!
    /// </summary>
    [HttpPost("service-token-no-expiry")]
    public IActionResult GenerateServiceTokenWithoutExpiry(
        [FromQuery] string serviceName = "billing-worker",
        [FromQuery] int notBeforeOffsetMinutes = 0)
    {
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(notBeforeOffsetMinutes);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSettings.SecretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

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
                ? $"Service token WITHOUT 'exp', but 'nbf' is {notBeforeOffsetMinutes} min in the future (will return 401!)"
                : "Service token WITHOUT 'exp' (will be ACCEPTED by custom ValidateTokenLifetime!)",
            Token = tokenString,
            NotBeforeUtc = notBefore.UtcDateTime,
            ExpiresUtc = (DateTime?)null
        });
    }

    /// <summary>
    /// 3. Generate an already-expired token so you can test 401 Unauthorized.
    /// </summary>
    [HttpPost("expired-token")]
    public IActionResult GenerateExpiredToken([FromQuery] string username = "alice")
    {
        var utcNow = DateTime.UtcNow;
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSettings.SecretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

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
            Scenario = "Expired token (expired 10 minutes ago -> calling protected endpoints will return 401 Unauthorized)",
            Token = tokenString,
            NotBeforeUtc = utcNow.AddMinutes(-20),
            ExpiresUtc = utcNow.AddMinutes(-10)
        });
    }

    /// <summary>
    /// 4. Inspect/decode any JWT token string without validating its signature or lifetime,
    /// so you can see the raw Header and Payload claims.
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
