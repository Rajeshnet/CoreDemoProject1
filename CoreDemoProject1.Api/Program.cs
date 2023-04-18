using Application;
using Infrastructure.Identity;
using Infrastructure.Persistence;
using Infrastructure.Shared;
using CoreDemoProject1.Api;
using CoreDemoProject1.Api.Extensions;

var builder = WebApplication.CreateBuilder(args);

//var builder = WebApplication.CreateBuilder(args).SetBasePath(app.Environment.ContentRootPath)
//        .AddJsonFile($"appsettings.json", optional: false, reloadOnChange: true)
//        .AddJsonFile($"appsettings{app.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
//        .AddEnvironmentVariables();
// Add services to the container. 
builder.Services.AddCoreDemoProject1Api();
builder.Services.AddApplicationLayer();
//builder.Services.AddIdentityInfrastructure(builder.Configuration);
builder.Services.AddPersistenceInfrastructure(builder.Configuration);
builder.Services.AddSharedInfrastructure(builder.Configuration);
builder.Services.AddSwaggerExtension();
builder.Services.AddControllers();
builder.Services.AddApiVersioningExtension();
builder.Services.AddHealthChecks();
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

await Infrastructure.Identity.ServiceExtensions.SeedData(app);
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
//app.Use(async (context, next) =>
//{
//    if (!context.User.Identity?.IsAuthenticated ?? false)
//    {
//        context.Response.StatusCode = 401;
//        await context.Response.WriteAsync("Not Authenticated!");
//    }
//    else await next();
//}); 
app.MapControllers(); 
app.Run();

