using Application.Interfaces.Services;
using Application.Services;

namespace CoreDemoProject1.Api
{
    public static class ServiceRegistration
    {
        public static void AddCoreDemoProject1Api(this IServiceCollection services)
        {
            services.AddTransient<IProductService, ProductService>();
        }
    }
}
