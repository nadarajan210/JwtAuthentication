using Microsoft.AspNetCore.Identity;
using System;

namespace JwtApp.Authentication
{
    public class ApplicationUser : IdentityUser
    {
        public DateTime CreatedOn { get; internal set; }
        public DateTime LastUpdatedOn { get; internal set; }
        public DateTime LastLoginOn { get; internal set; }
    }
}
