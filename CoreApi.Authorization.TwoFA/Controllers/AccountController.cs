using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using CoreApi.Authorization.TwoFA.Entities;
using CoreApi.Authorization.TwoFA.Security;
using CoreApi.Authorization.TwoFA.ViewModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace CoreApi.Authorization.TwoFA.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly SignInManager<AppUser> _signInManager;
        private readonly UserManager<AppUser> _userManager;
        private readonly IConfiguration _configuration;

        public AccountController(
            UserManager<AppUser> userManager,
            SignInManager<AppUser> signInManager,
            IConfiguration configuration
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpPost]
        public async Task<object> Login([FromForm] LoginVm model)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, false, false);

            if (result.Succeeded)
            {
                var appUser = _userManager.Users.SingleOrDefault(r => r.UserName == model.Username);
                return GenerateJwtToken(model.Username, appUser, false);
            }

            throw new ApplicationException("INVALID_LOGIN_ATTEMPT");
        }

        // Login
        [HttpPost]
        public async Task<IActionResult> LoginInitialAsync([FromBody] LoginVm model)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, false, false);

            if (result.Succeeded)
            {
                var appUser = _userManager.Users.SingleOrDefault(r => r.UserName == model.Username);
                var retVal = new
                {
                    user = appUser,
                    token = GenerateJwtToken(model.Username, appUser, true)
                };

                // Return User 
                return Ok(retVal);
            }

            throw new ApplicationException("INVALID_LOGIN_ATTEMPT");
        }

        [Authorize]
        [ServiceFilter(typeof(TwoFactorAuthFilter))]
        [HttpPost]
        public async Task<IActionResult> LoginWithOtpAsync([FromBody] LoginVm model)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, false, false);

            if (result.Succeeded)
            {
                var appUser = _userManager.Users.SingleOrDefault(r => r.UserName == model.Username);
                var retVal = new
                {
                    user = appUser,
                    token = GenerateJwtToken(model.Username, appUser, false)
                };

                // Return User 
                return Ok(retVal);
            }

            throw new ApplicationException("INVALID_LOGIN_ATTEMPT");
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUserVm model)
        {
            var user = new AppUser
            {
                UserName = model.Username,
                Email = model.Email,
                PSK = TimeSensitivePassCode.GeneratePresharedKey()
            };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, false);

                var retVal = new
                {
                    user,
                    token = GenerateJwtToken(model.Username, user, false)
                };
                // NOTE: Return the PSK to be able to register via Google/Microsoft Authenticator
                return Ok(retVal);
            }

            throw new ApplicationException("UNKNOWN_ERROR");
        }

        [Authorize]
        public IActionResult TestProtected()
        {
            return Json("Authorized!");
        }

        private object GenerateJwtToken(string username, AppUser user,bool isQuickExpire)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim("PSK",user.PSK)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.Now.AddDays(Convert.ToDouble(_configuration["JwtExpireDays"]));
            if (isQuickExpire)
            {
                expires = DateTime.Now.AddMinutes(10);
            }

            var token = new JwtSecurityToken(
                _configuration["JwtIssuer"],
                _configuration["JwtIssuer"],
                claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
