using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtLearningDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DemoController : ControllerBase
{
    /// <summary>
    /// 1. Public endpoint - no token required ([AllowAnonymous]).
    /// </summary>
    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult PublicEndpoint()
    {
        return Ok(new
        {
            Message = "Anyone can access this public endpoint without a JWT token!",
            IsAuthenticated = User.Identity?.IsAuthenticated ?? false
        });
    }

    /// <summary>
    /// 2. Protected endpoint - requires any valid JWT token ([Authorize]).
    /// Returns 401 Unauthorized if token is missing, expired, or has future notBefore.
    /// </summary>
    [HttpGet("protected")]
    [Authorize]
    public IActionResult ProtectedEndpoint()
    {
        return Ok(new
        {
            Message = $"Hello '{User.Identity?.Name}'! Your JWT token passed Authentication & ValidateTokenLifetime!",
            Username = User.Identity?.Name,
            Roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList(),
            AllClaims = User.Claims.Select(c => new { c.Type, c.Value }).ToList()
        });
    }

    /// <summary>
    /// 3. Role-protected endpoint - requires a valid JWT token WITH Role = "Admin".
    /// - Missing/expired token -> 401 Unauthorized
    /// - Valid token with Role = "User" -> 403 Forbidden
    /// - Valid token with Role = "Admin" -> 200 OK
    /// </summary>
    [HttpGet("admin-only")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminOnlyEndpoint()
    {
        return Ok(new
        {
            Message = $"Welcome Admin '{User.Identity?.Name}'! You passed both Authentication (401 check) and Authorization (403 Role check)."
        });
    }
}
