using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{

    private readonly ILogger<AuthController> _logger;

    private readonly IConfiguration _config;

    

    public AuthController(ILogger<AuthController> logger, IConfiguration config)
{
_config = config;
_logger = logger;
}

// Generer JWT token
private string GenerateJwtToken(string username)
{
    var secret = _config["Secret"];
    var issuer = _config["Issuer"];

    if (string.IsNullOrEmpty(secret))
    {
        _logger.LogError("Secret er ikke defineret i konfigurationen.");
        throw new ArgumentNullException(nameof(secret), "Secret er ikke defineret i konfigurationen.");
    }

    if (string.IsNullOrEmpty(issuer))
    {
        _logger.LogError("Issuer er ikke defineret i konfigurationen.");
        throw new ArgumentNullException(nameof(issuer), "Issuer er ikke defineret i konfigurationen.");
    }

    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, username)
    };

    // Tilføj roller baseret på brugernavn
    // Her kan du tilføje logik til at tildele roller baseret på brugernavn eller andre kriterier
    if (username == "haavy_user")
    {
        claims.Add(new Claim(ClaimTypes.Role, "user"));
    }
    else

    if (username == "admin")
    {
        claims.Add(new Claim(ClaimTypes.Role, "admin"));
    }

    var token = new JwtSecurityToken(
        issuer,
        audience: "http://localhost",
        claims,
        expires: DateTime.Now.AddMinutes(15),
        signingCredentials: credentials);

    return new JwtSecurityTokenHandler().WriteToken(token);
}

[AllowAnonymous]
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginModel login)
{
if ((login.Username == "haavy_user" && login.Password == "aaakodeord") ||
        (login.Username == "admin" && login.Password == "adminkodeord"))
{
var token = GenerateJwtToken(login.Username);
return Ok(new { token });
}
return Unauthorized();
}

}


