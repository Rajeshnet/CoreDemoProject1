using Application.DTOs.ReadDTO;
using AutoMapper;
using Domain.Entities;

namespace Application.Mappings
{
    public class GeneralProfile : Profile
    {
        public GeneralProfile()
        {
            CreateMap<Product, ProductRead>().ReverseMap();
            //CreateMap<Product, ProductRead>()
            //  .ForMember(dest => dest.ProductNo, opt => opt.MapFrom(src => src.ProductNumber))
            //  .ForMember(dest => dest.StandardCost, opt => opt.MapFrom(src => src.StandardCost > 1059 ? 0 : src.StandardCost));
        }
    }
}
