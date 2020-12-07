using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Microauth
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Bringing up Microauth");

            StartHostWithConfigFile(args, null, null);
        }

        private static IHostBuilder CreateHostBuilder(string[] args)
        {
            return Host.CreateDefaultBuilder(args)!
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    var b= webBuilder!;
                    b.UseStartup<Startup>();

                    if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASPNETCORE_URLS")))
                    {
                        b.UseUrls("https://localhost:6080");
                    }
                })!;
        }

        /// <summary>
        /// This is the core of Kestrel hosting. The 'Main' call above should always give `null` for the config path.
        /// The if you start this from your tests, you should pass the complete path to the appsettings.json file of the site being tested.
        /// </summary>
        public static void StartHostWithConfigFile(string[] args, string? configPath, string? basePath, string? extraConfig = null)
        {
            var host = CreateHostBuilder(args).ConfigureAppConfiguration(
                builder => {
                    if (configPath != null) builder.AddJsonFile(configPath);
                    if (extraConfig != null) builder.AddJsonFile(extraConfig);
                    if (basePath != null) builder.SetBasePath(basePath);
                }
            );
            if (basePath != null) host = host!.UseContentRoot(basePath);

            host?.Build()?.Run();
        }
    }
}