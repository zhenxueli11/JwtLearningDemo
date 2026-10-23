using System.IdentityModel.Tokens.Jwt;
using JwtLearningDemo;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Configure Swagger UI with an "Authorize" button for Bearer JWT tokens
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = ".NET 8 JWT Learning Demo (RS256 Private/Public Key)",
        Version = "v1",
        Description = "Step-by-step demo of RS256 JWT generation (Private Key), custom LifetimeValidator, and API validation (Public Key)."
    });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Paste your JWT token here (without the 'Bearer ' prefix)."
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ============================================================================
// 1. CONFIGURE AUTHENTICATION & JWT BEARER OPTIONS (USING RSA PUBLIC KEY ONLY!)
// ============================================================================
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // Verify the 'iss' (Issuer) claim
            ValidateIssuer = true,
            ValidIssuer = JwtSettings.Issuer,

            // Verify the 'aud' (Audience) claim
            ValidateAudience = true,
            ValidAudience = JwtSettings.Audience,

            // Verify the RS256 cryptographic signature using ONLY the RSA Public Key!
            // (Notice: Your API endpoint does NOT need or have the RSA Private Key)
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = JwtSettings.ApiEndpointPublicKey,

            // Verify 'nbf' (notBefore) and 'exp' (expires)
            ValidateLifetime = true,
            RequireExpirationTime = true,

            // ClockSkew allows a tolerance window (default in .NET is 5 minutes).
            // Set to 30 seconds here so you can easily test expiration!
            ClockSkew = TimeSpan.FromSeconds(30),

            // Custom LifetimeValidator that delegates to .NET's built-in Validators.ValidateLifetime
            LifetimeValidator = (notBefore, expires, securityToken, validationParameters) =>
                ValidateTokenLifetime(
                    notBefore,
                    expires,
                    securityToken,
                    validationParameters,
                    JwtSettings.AllowServiceTokenWithoutExpiry)
        };

        // Hook into JwtBearer middleware events so you can see what happens in the console
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                Console.WriteLine($"[JwtBearer] 1. OnMessageReceived -> Path: {context.HttpContext.Request.Path}");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                var name = context.Principal?.Identity?.Name ?? "(unnamed)";
                Console.WriteLine($"[JwtBearer] 2. OnTokenValidated  -> Authenticated user: {name}");
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"[JwtBearer] X. OnAuthenticationFailed -> {context.Exception.GetType().Name}: {context.Exception.Message}");
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                Console.WriteLine($"[JwtBearer] !. OnChallenge -> Returning 401 Unauthorized (Error: {context.ErrorDescription})");
                return Task.CompletedTask;
            },
            OnForbidden = context =>
            {
                Console.WriteLine("[JwtBearer] !. OnForbidden -> Returning 403 Forbidden (User is authenticated, but lacks required Role/Policy)");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

// ============================================================================
// 2. MIDDLEWARE PIPELINE ORDER MATTERS!
// ============================================================================
// Step A: UseAuthentication() reads the Authorization header, validates the JWT
//         (signature via RSA Public Key + lifetime via ValidateTokenLifetime),
//         and populates HttpContext.User.
app.UseAuthentication();

// Step B: UseAuthorization() checks [Authorize] / [Authorize(Roles = "...")] on
//         the target controller action using HttpContext.User.
//         - Not authenticated -> 401 Unauthorized
//         - Authenticated but wrong role -> 403 Forbidden
app.UseAuthorization();

app.MapControllers();

app.Run();

// ============================================================================
// 3. CUSTOM LIFETIME VALIDATOR (DELEGATING TO SYSTEM DEFAULT)
// ============================================================================
static bool ValidateTokenLifetime(
    DateTime? notBefore,
    DateTime? expires,
    SecurityToken securityToken,
    TokenValidationParameters validationParameters,
    bool allowServiceTokenWithoutExpiry)
{
    var allowMissingExpiry =
        allowServiceTokenWithoutExpiry && IsServiceToken(securityToken) && !expires.HasValue;

    var defaultParams = validationParameters.Clone();
    defaultParams.LifetimeValidator = null;

    if (allowMissingExpiry)
        defaultParams.RequireExpirationTime = false;

    Validators.ValidateLifetime(notBefore, expires, securityToken, defaultParams);
    return true;
}

static bool IsServiceToken(SecurityToken securityToken)
{
    // In .NET 8, JsonWebTokenHandler produces a JsonWebToken;
    // older JwtSecurityTokenHandler produces a JwtSecurityToken.
    if (securityToken is JsonWebToken jsonWebToken)
    {
        return jsonWebToken.TryGetPayloadValue<string>("token_type", out var type)
            && string.Equals(type, "service", StringComparison.OrdinalIgnoreCase);
    }

    if (securityToken is JwtSecurityToken jwtSecurityToken)
    {
        return jwtSecurityToken.Claims.Any(c =>
            c.Type == "token_type" &&
            string.Equals(c.Value, "service", StringComparison.OrdinalIgnoreCase));
    }

    return false;
}
