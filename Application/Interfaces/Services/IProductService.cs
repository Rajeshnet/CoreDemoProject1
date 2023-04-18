using Domain.Entities;

namespace Application.Interfaces.Services
{
    public interface IProductService
    {
        Task<Product> AddAsync(Product entity);
        Task DeleteAsync(Product entity);
        Task<IReadOnlyList<Product>> GetAllAsync();
        Task<Product> GetByIdAsync(int id);
        Task<IReadOnlyList<Product>> GetPagedReponseAsync(int pageNumber, int pageSize);
        Task<bool> IsUniqueBarcodeAsync(string barcode);
        Task UpdateAsync(Product entity);
    }
}