using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// ReSharper disable UnusedMember.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace Microauth
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
            services.AddCors(options => {
                options.AddPolicy("CorsPolicy",
                    builder => {
                        // Add any websites-under-test here:
                        builder.WithOrigins("http://localhost:5000", "https://localhost:5001")!
                            .AllowAnyHeader()!
                            .AllowAnyMethod();
                    });
            });
            
            services.AddControllers()! .ConfigureApiBehaviorOptions(options => {
                options.SuppressModelStateInvalidFilter = true;
                options.SuppressMapClientErrors = true;
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            
            app.UseHttpsRedirection();
            app.UseRouting();

            app.UseCors(builder => builder!
                .WithOrigins("http://localhost:5000", "https://localhost:5001")!
                .AllowAnyMethod()!
                .AllowAnyHeader()!
                .AllowCredentials()
            ); 

            app.UseAuthorization();
            
            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }
    }
}