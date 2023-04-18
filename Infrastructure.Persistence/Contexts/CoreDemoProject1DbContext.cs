using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistence.Contexts
{
    public class CoreDemoProject1DbContext : DbContext
    {
        public CoreDemoProject1DbContext(DbContextOptions<CoreDemoProject1DbContext> options) : base(options)
        {
        }
        public DbSet<Product> Products { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        { 
            base.OnModelCreating(builder);
        }
    }
}