using System.Security.Claims;

namespace DNE.CS.Inventory.Library.Interface
{
    public interface ITokenHandelar
    {
        Task<ClaimsPrincipal> UserInformation();
        Task<string?> GetAccessTokenAsync();
        Task<string?> RefreshToken();

    }
}
