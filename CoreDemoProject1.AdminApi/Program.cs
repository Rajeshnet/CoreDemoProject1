using CoreDemoProject1.AdminApi.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
              .AddJwtBearer(opt =>
              {
                  opt.Audience = builder.Configuration["Azure:ResourceId"];
                  opt.Authority = $"{builder.Configuration["Azure:Instance"]}{builder.Configuration["Azure:TenantId"]}";//Our AAD Instance that is the token issuing authority
              });
builder.Services.AddControllers(); 
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerExtension();

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
