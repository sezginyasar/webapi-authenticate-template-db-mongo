using webapiV2.Database;
using webapiV2.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using webapiV2.Helpers;
using System.Text.Json.Serialization;
using webapiV2.Authorization;

//var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddCors(
//     options => {
//     options.AddPolicy(name: MyAllowSpecificOrigins,
//                     policy => {
//                         policy.WithOrigins("http://localhost")
//                         .WithExposedHeaders("x-custom-header")
//                         .AllowCredentials()
//                         //.AllowAnyOrigin()
//                         .AllowAnyHeader()
//                         .AllowAnyMethod();
//                     });
// }
);
builder.Services.AddControllers()
    .AddJsonOptions(x => {
        x.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        x.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ayar nesneleri kısmı
builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

// database connection kısmı
builder.Services.Configure<DatabaseSettings>(
    builder.Configuration.GetSection("ConnectionStrings"));

builder.Services.AddScoped<IJwtUtils, JwtUtils>();
builder.Services.AddScoped<IAccountService, AccountService>();
builder.Services.AddScoped<IEmailService, EmailService>();

builder.Services.AddAuthentication(auth => {
    auth.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    auth.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(br => {
    br.RequireHttpsMetadata = false;
    br.SaveToken = true;
    br.TokenValidationParameters = new TokenValidationParameters {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.ASCII.GetBytes(
                builder.Configuration.GetSection("JwtKey").ToString() ?? "ymv/f8a65m7im+BXTK18XZzFB+x9IIP4l7rEeQ39VH8N5ZxAFTF6J6Nh0lX9Kzr7pWE+CmSd5+TBw0KTohn5CQ"
            )
        ),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
// global cors policy
app.UseCors(
    //MyAllowSpecificOrigins
    x => x
    .SetIsOriginAllowed(origin => true)
    //.AllowAnyOrigin()
    .AllowAnyMethod()
    .AllowAnyHeader()
    .AllowCredentials()
    );

// global error handler
app.UseMiddleware<ErrorHandlerMiddleware>();
// custom jwt auth middleware
app.UseMiddleware<JwtMiddleware>();

if (app.Environment.IsDevelopment()) {
    app.UseSwagger();
    app.UseSwaggerUI(x => x.SwaggerEndpoint("/swagger/v1/swagger.json", ".NET Sign-up and Verification API"));
}

app.UseHttpsRedirection();
//app.UseCookiePolicy();
app.UseAuthorization();

app.MapControllers();

app.Run();
