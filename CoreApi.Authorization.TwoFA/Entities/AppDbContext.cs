using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreApi.Authorization.TwoFA.Entities
{
    public class AppDbContext : IdentityDbContext<AppUser, AppRole, int>
    {
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlServer(GetConnectionString());
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            //builder.Entity<AppUser>().Ignore(e => e.FullName);
        }

        private static string GetConnectionString()
        {
            return "Data Source=sql5047.site4now.net;Initial Catalog=DB_A53ED9_NinjamonApiTest;User Id=DB_A53ED9_NinjamonApiTest_admin;Password=codemasters23";
        }
    }
}
