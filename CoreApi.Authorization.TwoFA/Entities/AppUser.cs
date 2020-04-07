using CoreApi.Authorization.TwoFA.Entities.Database;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CoreApi.Authorization.TwoFA.Entities
{
    // Extend IdentityUser
    public class AppUser : IdentityUser<int>
    {
        [Required]
        [MaxLength(16)]
        public string PSK { get; set; } // NOTE: This is the pre shared key that will be use by Google/Microsoft Authenticator
        public virtual Person Person { get; set; }
    }
}
