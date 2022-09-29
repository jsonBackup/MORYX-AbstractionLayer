using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Moryx.Runtime.Kernel;

namespace StartProject.Asp
{
    public static class Program
    {
        // This method is the application entry point; Main() is called when the app is started.
        public static int Main(string[] args)
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false)
                .Build();

            var moryxRuntime = new HeartOfGold(args);
            moryxRuntime.Load();
            var host = Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup(conf => new Startup(moryxRuntime, config));
                }).Build();

            host.Start();
            var result = moryxRuntime.Execute();
            host.Dispose();

            return (int)result;
        }
    }
}
