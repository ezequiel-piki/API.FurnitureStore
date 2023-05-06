using API.FurnitureStore.API.Configuration;
using API.FurnitureStore.API.Services;
using API.FurnitureStore.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen( c => 
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Furniture_Store_API",
        Version = "v1",
    });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = $@"JWT Authorization header using the bearer scheme.
                      \r\n\r\n Enter prefix (Bearer), Space, and then your token. +
                       Example. 'Bearer 123 jaosjadoas' ",

    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
        {
        new OpenApiSecurityScheme{
            Reference = new OpenApiReference{ Type = ReferenceType.SecurityScheme, Id = "Bearer"}
        },
          new string [] {}
        }
    });
}

);



builder.Services.AddDbContext<APIFurnitureStoreContext>(options =>options.UseSqlite(builder.Configuration.GetConnectionString("APIFurnitureStoreContext")));

builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection("JwtConfig"));

//Email
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
builder.Services.AddSingleton<IEmailSender, EmailService>();

var key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("JwtConfig:Secret").Value);
var tokenValidationParameters = new TokenValidationParameters()
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = false,
    ValidateAudience = false,
    ValidateLifetime = false,
};

builder.Services.AddSingleton(tokenValidationParameters);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer( jwt =>
{
   
    jwt.SaveToken = true;
    jwt.TokenValidationParameters = tokenValidationParameters;
} 
);
builder.Services.AddDefaultIdentity<IdentityUser>(options =>
options.SignIn.RequireConfirmedAccount = false)
    .AddEntityFrameworkStores<APIFurnitureStoreContext>();



var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
