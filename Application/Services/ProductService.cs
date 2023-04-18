using Application.Interfaces.Repositories;
using Application.Interfaces.Services;
using AutoMapper;
using Domain.Entities;

namespace Application.Services
{
    public class ProductService : IProductRepositoryAsync, IProductService
    {
        private readonly IProductRepositoryAsync _productRepository;
        private readonly IMapper _mapper;
        public ProductService(IProductRepositoryAsync productRepository, IMapper mapper)
        {
            _productRepository = productRepository;
            _mapper = mapper;
        }
        public Task<bool> IsUniqueBarcodeAsync(string barcode)
        {
            throw new NotImplementedException();
        }

        public async Task<Product> GetByIdAsync(int id)
        {
            return await _productRepository.GetByIdAsync(id);
        }

        public async Task<IReadOnlyList<Product>> GetAllAsync()
        {
            return await _productRepository.GetAllAsync();
        }

        public Task<IReadOnlyList<Product>> GetPagedReponseAsync(int pageNumber, int pageSize)
        {
            throw new NotImplementedException();
        }

        public Task<Product> AddAsync(Product entity)
        {
            throw new NotImplementedException();
        }

        public Task UpdateAsync(Product entity)
        {
            throw new NotImplementedException();
        }

        public Task DeleteAsync(Product entity)
        {
            throw new NotImplementedException();
        }
    }
}
