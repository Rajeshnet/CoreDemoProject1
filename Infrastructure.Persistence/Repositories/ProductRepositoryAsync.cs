using Application.Interfaces.Repositories;
using Domain.Entities;
using Infrastructure.Persistence.Contexts;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistence.Repositories
{
    public class ProductRepositoryAsync : GenericRepositoryAsync<Product>, IProductRepositoryAsync
    {
        private readonly DbSet<Product> _products;

        public ProductRepositoryAsync(CoreDemoProject1DbContext dbContext) : base(dbContext)
        {
            _products = dbContext.Set<Product>();
        }
        public Task<bool> IsUniqueBarcodeAsync(string barcode)
        {
            return null;
        }
    }
}
