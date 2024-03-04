using System.Security.Claims;

namespace DNE.CS.Inventory.Library.Interface
{
    public interface ITokenHandelar
    {
        Task<ClaimsPrincipal> UserInformation();
        ClaimsPrincipal UserInformation(string accessToken);
        Task<string?> GetAccessTokenAsync();
        Task<string?> RefreshToken();
        Task SetTokenAsync(string accessToken, string refreshToken);
        Task ClearTokenAsync();
    }
}
