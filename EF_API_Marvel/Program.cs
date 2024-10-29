
using EF_API_Marvel.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace EF_API_Marvel
{
    public class Program
    {
        static DbApiContext db = new DbApiContext();
        public static async void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddDbContext<DbApiContext>(options => options.UseSqlServer("data source=labVMH8OX\\SQLEXPRESS;initial catalog=dbAPI;integrated Security=True; Encrypt=False;"));


            #region Set up region
            builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<DbApiContext>().AddDefaultTokenProviders();

            #endregion


            // Add services to the container.
            builder.Services.AddAuthorization();

            builder.Services.AddEndpointsApiExplorer();

            #region Swagger add bearer to top

            builder.Services.AddSwaggerGen(opt =>
            {
                opt.SwaggerDoc("v1", new OpenApiInfo { Title = "EF_API_Marvel", Version = "v1" });
                opt.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Please enter token",
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    BearerFormat = "JWT",
                    Scheme = "bearer"
                });
                opt.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type=ReferenceType.SecurityScheme,
                                Id="Bearer"
                            }
                        },
                        new string[]{}
                    }
                });
            });
            #endregion
            var app = builder.Build();

            #region Create roles
            using (var scope = app.Services.CreateScope())
            {
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                await EnsureRolesAsync(roleManager);
            }
            #endregion
            
            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
                {
                    app.UseSwagger();
                    app.UseSwaggerUI();
                }

            app.UseHttpsRedirection();
            app.UseAuthentication(); //need this, dont forget to add it
            app.UseAuthorization();

            #region Add user and check admin or user
            app.MapPost("/register", async (UserRegistrationDto model, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager) =>
            {
                var user = new IdentityUser { UserName = model.Username, Email = model.Email };
                var result = await userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, model.Role);
                    return Results.Created($"/users/{user.UserName}", user);
                }
                return Results.BadRequest(result.Errors);
            }).WithName("RegisterUser").WithOpenApi();

            app.MapPost("/login", async (UserLoginDto model, SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager) =>
            {
                var user = await userManager.FindByNameAsync(model.Username);
                if (user != null)
                {
                    var result = await signInManager.PasswordSignInAsync(model.Username, model.Password, false, false);
                    if (result.Succeeded)
                    {
                        var token = GenerateJwtToken(user, userManager);
                        return Results.Ok(new { Token = token });
                    }
                }
                return Results.Unauthorized();
            }).WithName("LoginUser").WithOpenApi();
            app.MapGet("/admin", [Authorize(Roles = "Admin")] () => "Welcome Admin").WithName("AdminEndpoint").WithOpenApi();
            app.MapGet("/user", [Authorize(Roles = "User")] () => "Welcome User").WithName("UserEndpoint").WithOpenApi();
            #endregion


            // GET endpoints
            app.MapGet("/users", () => db.TblAvengers.ToList())
                .WithName("GetUsers")
                .WithOpenApi();

            app.MapGet("/contacts", () => db.TblContacts.ToList())
                .WithName("GetContacts")
                .WithOpenApi();

            //POST endpoint
            app.MapPost("/users", (TblAvenger newUser) =>
            {
                db.TblAvengers.Add(newUser);
                db.SaveChanges();
                return Results.Created($"/users/{newUser.Username}", newUser);
            }).WithName("CreateUser").WithOpenApi();

            app.MapPost("/contacts", (TblContact newContact) =>
            {
                db.TblContacts.Add(newContact);
                db.SaveChanges();
                return Results.Created($"/contacts/{newContact.HeroName}", newContact);
            }).WithName("CreateContact").WithOpenApi();

            //PUT endpoints
            app.MapPut("/users/{username}", (string username, TblAvenger updatedUser) =>
            {
                var user = db.TblAvengers.FirstOrDefault(u => u.Username == username);
                if (user != null)
                {
                    user.Password = updatedUser.Password; //update necessary fields
                    db.SaveChanges();
                    return Results.NoContent();
                }
                return Results.NotFound();
            }).WithName("UpdateUser").WithOpenApi();

            app.MapPut("/contacts/{id}", (int id, TblContact updateedContact) =>
            {
                var contact = db.TblContacts.FirstOrDefault(c => c.AvengerId == id);
                if (contact != null)
                {
                    contact.HeroName = updateedContact.HeroName; //update necessary fields
                    contact.RealName = updateedContact.RealName;
                    db.SaveChanges();
                    return Results.NoContent();
                }
                return Results.NotFound();
            }).WithName("UpdateContact").WithOpenApi();

            //DELETE endpoints
            app.MapDelete("/users/{username}", (string username) =>
            {
                try
                {
                    DbApiContext dbApiContext = new DbApiContext();

                    var user = db.TblAvengers.FirstOrDefault(u => u.Username == username);
                    if (user != null)
                    {
                        db.TblAvengers.Remove(user);
                        db.SaveChanges();
                        db.Dispose();
                        return Results.NoContent();
                    }
                }

                catch (Exception ex)
                {
                    return Results.Conflict();
                }
                return Results.NotFound();
            }).WithName("DeleteUser").WithOpenApi();

            app.MapDelete("/contacts/{id}", (int id) =>
            {
                var contact = db.TblContacts.FirstOrDefault(c => c.AvengerId == id);
                if (contact != null)
                {
                    db.TblContacts.Remove(contact);
                    db.SaveChanges();
                    return Results.NoContent();
                }
                return Results.NotFound();
            }).WithName("DeleteContact").WithOpenApi();

            app.Run();
        }
        #region Generate JWT Token with user rights
        private static string GenerateJwtToken(IdentityUser user, UserManager<IdentityUser> userManager)
        {
            var userRoles = userManager.GetRolesAsync(user).Result;
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("NtD9o+gpE1IjeqvEXXhh64Q3UrBnYKA4aCePsWQtfn8="));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "MarvelAPI",
                audience: "marvelAPI",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        #endregion
        #region Add user roles to DB
        private static async Task EnsureRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            var roles = new[] { "Admin", "User" };
            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }
        }
        #endregion
    }
}
