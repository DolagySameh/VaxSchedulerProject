using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using vaxScheduler.Data.Model;
using vaxScheduler.Data;
using vaxScheduler.models;
using vaxScheduler.models.repos;

namespace vaxScheduler.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Account : ControllerBase
    {

        public Account(IRepository repo)
        {
            _repo = repo;
        }
        private readonly IRepository _repo;



        /*                                   Hashing Password                               */
        [NonAction]
        [ApiExplorerSettings(IgnoreApi = true)]
        public string HashPassword(string password)
        {
            return _repo.HashPassword(password);
        }

        /*                                   Patient_register                                               */
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            return await _repo.Register(registerDto);
        }

        /*                                          Login                                              */
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginDto loginDto)
        {
            return _repo.Login(loginDto);
        }


        /*                                      generate Token                                     */
        [NonAction]
        [ApiExplorerSettings(IgnoreApi = true)]
        public string GenerateToken(List<Claim> claims)
        {
            return _repo.GenerateToken(claims);
        }

        /*                                     logout                                               */
        [HttpPost("logout")]
        public IActionResult ALogout()
        {
            return _repo.ALogout();
        }



    }
}
