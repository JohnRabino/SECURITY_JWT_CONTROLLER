using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SECURITY_JWT_CONTROLLER.Models;

namespace SECURITY_JWT_CONTROLLER.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private static readonly List<User> _users = new();
    private static int _nextId = 1;
    private static readonly PasswordHasher<User> _hasher = new();
    private readonly IConfiguration _config;

    public AuthController(IConfiguration config) => _config = config;

    public record AuthRequest(string Username, string Password);

    private int GetNextId()
    {
        for (int i = 1; i < _nextId; i++)
        {
            if (!_users.Any(u => u.Id == i))
                return i;
        }
        return _nextId++;
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult Register(AuthRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
            return BadRequest("Username and password are required.");

        if (_users.Any(u => u.Username == req.Username))
            return BadRequest("Username already taken.");

        var user = new User { Id = GetNextId(), Username = req.Username };
        user.Role = (req.Username == "admin") ? "Admin" : "User";
        user.PasswordHash = _hasher.HashPassword(user, req.Password);
        _users.Add(user);

        return Created("", new { user.Id, user.Username });
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public IActionResult Login(AuthRequest req)
    {
        var user = _users.FirstOrDefault(u => u.Username == req.Username);
        if (user is null) return Unauthorized("Invalid credentials.");

        var check = _hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password);
        if (check == PasswordVerificationResult.Failed)
            return Unauthorized("Invalid credentials.");

        return Ok(new { token = CreateToken(user) });
    }

    [Authorize(Roles = "Admin")]
    [HttpDelete("{id}")]
    public IActionResult Delete(int id)
    {
        var user = _users.FirstOrDefault(u => u.Id == id);
        if (user is null) return NotFound("User not found.");

        _users.Remove(user);
        return NoContent();
    }

    [Authorize(Roles = "Admin")]
    [HttpGet]
    public IActionResult GetAll() =>
        Ok(_users.Select(u => new { u.Id, u.Username, u.Role }));

    private string CreateToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(int.Parse(_config["Jwt:ExpiryMinutes"]!)),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}