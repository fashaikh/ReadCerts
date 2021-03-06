﻿using System;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace ReadCerts
{
    public class Startup
    {
        private IHostingEnvironment _env;

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            _env = env;

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.Run(async (context) =>
            {
                await context.Response.WriteAsync(certInfo());
            });
        }
        private string certInfo()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append($"<html><body><h2>Reading certs in 'CurrentUserMy'</h2><br/>");
            try
            {
                X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                certStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certCollection = certStore.Certificates;

                // Get the first cert with the thumbprint
                if (certCollection.Count > 0)
                {
                    foreach (X509Certificate2 cert in certCollection)
                    {
                        if (!cert.Subject.Contains("azure", StringComparison.OrdinalIgnoreCase) && !cert.Subject.Contains("FullOSTransport", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                sb.Append($"cert.Thumbprint: {cert.Thumbprint}<br/>");
                            }
                            catch { }
                            try
                            {
                                sb.Append($"cert.HasPrivateKey: {cert.HasPrivateKey}<br/>");
                            }
                            catch { }
                            try
                            {
                                sb.Append($"cert.Issuer: {cert.Issuer}<br/>");
                            }
                            catch { }
                            try
                            {
                                sb.Append($"cert.Subject: {cert.Subject}<br/>");
                            }
                            catch { }
                            sb.Append($"==========================================<br/>");


                        }
                    }
                }
                else
                {
                    sb.Append($"NO CERTS FOUND in 'CurrentUserMy' !!<br/>");
                }
                certStore.Close();
            }
            catch (Exception ex){
                sb.Append($"Exception reading certs in 'CurrentUserMy':{ex.ToString()}<br/>");

            }
            try
            {
                sb.Append($"<br/><br/><h2>Reading certs in 'LocalMachineMy'</h2><br/>");
                X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                certStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certCollection = certStore.Certificates;

                // Get the first cert with the thumbprint
                if (certCollection.Count > 0)
                {
                    foreach (X509Certificate2 cert in certCollection)
                    {
                        if (!cert.Subject.Contains("azure", StringComparison.OrdinalIgnoreCase) && !cert.Subject.Contains("FullOSTransport", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                sb.Append($"cert.Thumbprint: {cert.Thumbprint}<br/>");
                            }
                            catch { }
                            try
                            {
                                sb.Append($"cert.HasPrivateKey: {cert.HasPrivateKey}<br/>");
                            }
                            catch { }
                            try
                            {
                                sb.Append($"cert.Issuer: {cert.Issuer}<br/>");
                            }
                            catch { }
                            try
                            {
                                sb.Append($"cert.Subject: {cert.Subject}<br/>");
                            }
                            catch { }
                            sb.Append($"==========================================<br/>");
                        }

                    }
                }
                else
                {
                    sb.Append($"NO CERTS FOUND in 'LocalMachineMy' !!<br/>");
                }
                certStore.Close();
            }
            catch (Exception ex)
            {
                sb.Append($"Exception reading certs in 'LocalMachineMy':{ex.ToString()}<br/>");

            }
            try
            {
                sb.Append($"<br/><br/><h2>Reading Private Key from pfx on disk /App_Data/</h2><br/>");
                X509Certificate2 cert = new X509Certificate2
                    (_env.ContentRootPath + "/App_Data/certsanddomaintests.pfx", File.ReadAllText(_env.ContentRootPath + "/App_Data/password.txt"),
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

            if (!cert.Subject.Contains("azure", StringComparison.OrdinalIgnoreCase) && !cert.Subject.Contains("FullOSTransport", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                sb.Append($"cert.Thumbprint: {cert.Thumbprint}<br/>");
                            }
                            catch { }
                            try
                            {
                                sb.Append($"cert.HasPrivateKey: {cert.HasPrivateKey}<br/>");
                            }
                            catch { }
                            try
                            {
                                AsymmetricAlgorithm key = cert.PrivateKey;
                                sb.Append($"privateKey.KeySize: {key.KeySize}<br/>");
                                sb.Append($"privateKey.SignatureAlgorithm: {key.SignatureAlgorithm}<br/>");
                                sb.Append($"privateKey.KeyExchangeAlgorithm: {key.KeyExchangeAlgorithm}<br/>");
                            }
                            catch { }
                            try
                            {
                                sb.Append($"cert.Issuer: {cert.Issuer}<br/>");
                            }
                            catch { }
                            try
                            {
                                sb.Append($"cert.Subject: {cert.Subject}<br/>");
                            }
                            catch { }
                            sb.Append($"==========================================<br/>");
                        }
                else
                {
                    sb.Append($"Unable to read private CERT in App_Data !!<br/>");
                }
            }
            catch (Exception ex)
            {
                sb.Append($"Exception reading private CERT in App_Data :{ex.ToString()}<br/>");

            }

            sb.Append("</body></html>");
            return sb.ToString();
        }
        
    }
}
