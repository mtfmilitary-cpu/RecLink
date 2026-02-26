using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BCrypt.Net;

// Setup
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication("RecLinkCookie")
.AddCookie("RecLinkCookie", options =>
{
options.LoginPath = "/login";
options.Cookie.Name = "RecLinkAuth";
options.ExpireTimeSpan = TimeSpan.FromDays(7);
});
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// In-memory stores (replace with DB for production)
var users = new Dictionary<string, UserAccount>();
var rooms = new Dictionary<string, RoomData>();
var players = new Dictionary<string, PlayerProfile>();

// ===== REGISTER =====
app.MapPost("/register", async (HttpContext context) =>
{
var data = await JsonSerializer.DeserializeAsync<AuthRequest>(context.Request.Body);
if (data == null || string.IsNullOrEmpty(data.Email) || string.IsNullOrEmpty(data.Password))
return Results.BadRequest("Invalid input");

if (users.ContainsKey(data.Email))
return Results.BadRequest("Email already exists");

users[data.Email] = new UserAccount
{
Email = data.Email,
PasswordHash = BCrypt.Net.BCrypt.HashPassword(data.Password)
};

return Results.Ok("Registered");
});

// ===== LOGIN =====
app.MapPost("/login", async (HttpContext context) =>
{
var data = await JsonSerializer.DeserializeAsync<AuthRequest>(context.Request.Body);
if (data == null || !users.ContainsKey(data.Email))
return Results.Unauthorized();

var user = users[data.Email];
if (!BCrypt.Net.BCrypt.Verify(data.Password, user.PasswordHash))
return Results.Unauthorized();

var claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Email) };
var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "RecLinkCookie"));
await context.SignInAsync("RecLinkCookie", principal);

return Results.Ok("Logged In");
});

// ===== DASHBOARD =====
app.MapGet("/dashboard", (HttpContext context) =>
{
if (!context.User.Identity.IsAuthenticated)
return Results.Unauthorized();

return Results.Ok(new { MemberCount = players.Count, Members = players.Values });
});

// ===== ROOM REGISTER =====
app.MapPost("/register-room", async (HttpContext context) =>
{
if (!context.User.Identity.IsAuthenticated)
return Results.Unauthorized();

var data = await JsonSerializer.DeserializeAsync<RoomRegisterRequest>(context.Request.Body);
if (data == null || string.IsNullOrEmpty(data.RoomId))
return Results.BadRequest();

string token = GenerateSecureToken();
string hashed = Hash(token);

rooms[data.RoomId] = new RoomData
{
OwnerEmail = context.User.Identity.Name,
HashedToken = hashed
};

return Results.Ok(new { Token = token });
});

// ===== PLAYER VERIFY =====
app.MapPost("/verify-player", async (HttpContext context) =>
{
var data = await JsonSerializer.DeserializeAsync<PlayerVerifyRequest>(context.Request.Body);
if (data == null || !rooms.ContainsKey(data.RoomId))
return Results.Unauthorized();

var room = rooms[data.RoomId];
if (room.HashedToken != Hash(data.Token))
return Results.Unauthorized();

if (!players.ContainsKey(data.PlayerId))
return Results.NotFound();

return Results.Ok(players[data.PlayerId]);
});

app.Run();

// ===== UTILITIES =====
string GenerateSecureToken()
{
var rng = RandomNumberGenerator.Create();
var bytes = new byte[32];
rng.GetBytes(bytes);
return Convert.ToBase64String(bytes);
}

string Hash(string input)
{
using var sha = SHA256.Create();
return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(input)));
}

// ===== DATA MODELS =====
public record AuthRequest(string Email, string Password);
public record RoomRegisterRequest(string RoomId);
public record PlayerVerifyRequest(string RoomId, string Token, string PlayerId);

public class UserAccount
{
public string Email { get; set; }
public string PasswordHash { get; set; }
}

public class RoomData
{
public string OwnerEmail { get; set; }
public string HashedToken { get; set; }
}

public class PlayerProfile
{
public string PlayerId { get; set; }
public bool IsTrained { get; set; }
public bool IsAntiCrasher { get; set; }
public bool IsCrasher { get; set; }
public bool IsBlacklisted { get; set; }
public string BlacklistReason { get; set; }
public int SubscriberCount { get; set; }
public int Level { get; set; }
}
