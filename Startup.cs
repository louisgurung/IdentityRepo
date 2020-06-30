using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityNetCore.Data;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace IdentityNetCore
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<DataContextIdentity>(Options => Options.UseSqlServer(Configuration.GetConnectionString("DataContext")));
           // services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<DataContextIdentity>();
            services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<DataContextIdentity>().AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequiredLength = 3;
                options.Password.RequireDigit = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;

                //options.Lockout.MaxFailedAccessAttempts = 3;
                //options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);

                //options.SignIn.RequireConfirmedEmail = true;

            });
            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Identity/SignIn";
                options.AccessDeniedPath = "/Identity/AccessDenied";
                options.ExpireTimeSpan = TimeSpan.FromSeconds(5);     //cookie validation ...rememberMe??
            });
            services.Configure<SmtpOptions>(Configuration.GetSection("Smtp")); //this line for configuring smtp
            services.AddSingleton<IEmailSender, SmtpEmailSender>();

            //useful for authorization based on age criteria, have certain degree   ROLE AND CLAIMS COMBINATION
            services.AddAuthorization(option=> {
                option.AddPolicy("MemberDep", p => p.RequireClaim("Department", "tech").RequireRole("Member"));
                option.AddPolicy("AdminDep", p => p.RequireClaim("Department", "tech").RequireRole("Admin"));

            });
            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
