using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SecurityHeaderScannerGUI
{
    public static class SecurityAnalyzer
    {
        static readonly HttpClient _http = new HttpClient() { Timeout = TimeSpan.FromSeconds(20) };

        static readonly Dictionary<string, string> ReferenceHeaders = new()
        {
            ["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload",
            ["X-Frame-Options"] = "SAMEORIGIN",
            ["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
            ["X-Content-Type-Options"] = "nosniff",
            ["Referrer-Policy"] = "no-referrer",
            ["Permissions-Policy"] = "", // método CheckPermissionsPolicy
            ["Cross-Origin-Opener-Policy"] = "same-origin",
            ["Cross-Origin-Resource-Policy"] = "same-origin",
            ["Cross-Origin-Embedder-Policy"] = "require-corp OR credentialless"
        };

        static readonly string WARNING = "!warning!";

        public static async Task<ReportItem> AnalyzeUrl(string url)
        {
            var item = new ReportItem { Url = url, TimestampUtc = DateTime.UtcNow };
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                using var res = await _http.SendAsync(req);
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var h in res.Headers) headers[h.Key] = string.Join("; ", h.Value);
                foreach (var h in res.Content.Headers) headers[h.Key] = string.Join("; ", h.Value);
                item.Headers = headers;

                item.Comparisons = CompareWithReference(headers);
            }
            catch (Exception ex)
            {
                item.Error = ex.Message;
            }
            return item;
        }

        public static ComparisonsResult CompareWithReference(Dictionary<string, string> headers)
        {
            var result = new ComparisonsResult();
            var headerResults = new List<HeaderCheckResult>();

            foreach (var kv in ReferenceHeaders)
            {
                headers.TryGetValue(kv.Key, out var actual);

                if (actual == null) continue;

                var expected = kv.Value;
                var hr = new HeaderCheckResult { Name = kv.Key, Expected = expected, Actual = actual };

                if (string.Equals(kv.Key, "Strict-Transport-Security", StringComparison.OrdinalIgnoreCase))
                {
                    hr = CheckHsts(expected, actual);
                }
                else if (string.Equals(kv.Key, "Content-Security-Policy", StringComparison.OrdinalIgnoreCase))
                {
                    hr = CheckCsp(expected, actual);
                }
                else if (string.Equals(kv.Key, "Cross-Origin-Embedder-Policy", StringComparison.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrEmpty(actual))
                    {
                        hr.Passed = false;
                        hr.Message = "header ausente";
                    }
                    else if (Normalize(actual) == "require-corp")
                    {
                        hr.Passed = true;
                        hr.Message = string.Empty;
                    }
                    else if (Normalize(actual) == "credentialless")
                    {
                        hr.Passed = false;
                        hr.Message = WARNING + " Valor permitido, mas menos seguro que require-corp";
                    }
                    else
                    {
                        hr.Passed = false;
                        hr.Message = "valor diferente";
                    }

                    headerResults.Add(hr);
                    continue;
                }
                else if (string.Equals(kv.Key, "Referrer-Policy", StringComparison.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrEmpty(actual))
                    {
                        hr.Passed = false;
                        hr.Message = "header ausente";
                    }
                    else if (Normalize(actual) == "no-referrer")
                    {
                        hr.Passed = true;
                        hr.Message = string.Empty;
                    }
                    else
                    {
                        hr.Passed = false;
                        hr.Message = WARNING + " Valor permitido, mas menos seguro que no-referrer";
                    }

                    headerResults.Add(hr);
                    continue;
                }
                else if (string.Equals(kv.Key, "Permissions-Policy", StringComparison.OrdinalIgnoreCase))
                {
                    hr = CheckPermissionsPolicy(actual);
                    headerResults.Add(hr);
                    continue;
                }
                else
                {
                    hr.Passed = !string.IsNullOrEmpty(actual) && Normalize(actual) == Normalize(expected);
                    if (!hr.Passed && string.IsNullOrEmpty(actual)) hr.Message = "header ausente";
                    else if (!hr.Passed) hr.Message = "valor diferente";
                }

                headerResults.Add(hr);
            }

            result.HeaderChecks = headerResults;

            headers.TryGetValue("Server", out var server);
            headers.TryGetValue("X-Powered-By", out var xpb);
            result.ServerExposed = !string.IsNullOrEmpty(server) || !string.IsNullOrEmpty(xpb);
            result.ServerHeader = server;
            result.XPoweredBy = xpb;

            return result;
        }

        static string Normalize(string s) =>
            Regex.Replace((s ?? "").ToLowerInvariant(), @"\s+", "");

        public static HeaderCheckResult CheckPermissionsPolicy(string actual)
        {
            var mandatoryDisabled = new[]
{
                "usb",
                "serial",
                "hid",
                "bluetooth",
                "midi",
                "magnetometer",
                "gyroscope",
                "accelerometer"
            };

            var hr = new HeaderCheckResult
            {
                Name = "Permissions-Policy",
                Expected = "Diretivas mínimas esperadas: " + string.Join(", ", mandatoryDisabled),
                Actual = actual
            };

            if (string.IsNullOrEmpty(actual))
            {
                hr.Passed = false;
                hr.Message = "header ausente";
                return hr;
            }

            var policy = ParsePermissionsPolicy(actual);

            var missingMandatory = mandatoryDisabled
                .Where(d => !policy.ContainsKey(d))
                .ToList();

            if (missingMandatory.Any())
            {
                hr.Passed = false;

                hr.Expected = "Obrigatório declarar: " +
                                  string.Join(", ", missingMandatory.Select(d => $"{d}=()"));

                hr.Message = "Diretivas mínimas ausentes: " +
                             string.Join(", ", missingMandatory);

                return hr;
            }

            // Apenas alerta
            var sensitiveGov = new[]
            {
                "camera",
                "microphone",
                "geolocation",
                "fullscreen"
            };

            var warnings = sensitiveGov
                .Where(d => policy.ContainsKey(d) && policy[d] != "()")
                .ToList();

            hr.Passed = true;

            if (warnings.Any())
            {
                hr.Message = WARNING +
                    " Diretivas sensíveis ativas — validar necessidade funcional: " +
                    string.Join(", ", warnings);
            }
            else
            {
                hr.Message = "OK";
            }

            return hr;
        }

        public static Dictionary<string, string> ParsePermissionsPolicy(string header)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            var parts = header.Split(',')
                .Select(p => p.Trim())
                .Where(p => !string.IsNullOrEmpty(p));

            foreach (var p in parts)
            {
                if (p.Contains('='))
                {
                    var sp = p.Split('=', 2);
                    dict[sp[0].Trim()] = sp[1].Trim();
                }
                else
                {
                    dict[p.Trim()] = "true";
                }
            }

            return dict;
        }

        public static HeaderCheckResult CheckHsts(string expected, string actual)
        {
            var hr = new HeaderCheckResult { Name = "Strict-Transport-Security", Expected = expected, Actual = actual };
            if (string.IsNullOrEmpty(actual))
            {
                hr.Passed = false;
                hr.Message = "header ausente";
                return hr;
            }

            var map = ParseDirectiveMap(actual);

            if (!map.TryGetValue("max-age", out var maxAgeRaw) || !long.TryParse(maxAgeRaw, out var maxAge))
            {
                hr.Passed = false;
                hr.Message = "max-age ausente ou inválido";
                return hr;
            }

            var include = map.ContainsKey("includesubdomains") || map.ContainsKey("includeSubDomains");
            var preload = map.ContainsKey("preload");

            hr.Passed = maxAge >= 31536000 && include && preload;

            var msgs = new List<string>();
            if (maxAge < 31536000) msgs.Add($"max-age={maxAge} < 31536000");
            if (!include) msgs.Add("includeSubDomains ausente");
            if (!preload) msgs.Add("preload ausente");
            hr.Message = msgs.Count == 0 ? "OK" : string.Join("; ", msgs);

            return hr;
        }

        public static HeaderCheckResult CheckCsp(string expected, string actual)
        {
            var hr = new HeaderCheckResult
            {
                Name = "Content-Security-Policy",
                Expected = "Obrigatórias: default-src 'self'; script-src 'self'",
                Actual = actual
            };

            if (string.IsNullOrEmpty(actual))
            {
                hr.Passed = false;
                hr.Message = "header ausente";
                return hr;
            }

            var actualMap = ParseCspDirectives(actual);

            // Diretivas obrigatórias
            var mandatory = new Dictionary<string, string>
            {
                ["default-src"] = "'self'",
                ["script-src"] = "'self'"
            };

            var missingMandatory = new List<string>();

            foreach (var m in mandatory)
            {
                if (!actualMap.TryGetValue(m.Key, out var value) || !value.Contains(m.Value))
                    missingMandatory.Add(m.Key);
            }

            if (missingMandatory.Any())
            {
                hr.Passed = false;
                hr.Expected = "Obrigatórias: default-src 'self'; script-src 'self'";
                hr.Message = "Faltando obrigatórias: " + string.Join(", ", missingMandatory);
                return hr;
            }

            // Diretivas recomendadas (alerta apenas)
            var expectedMap = ParseCspDirectives(expected);
            var warnings = new List<string>();

            foreach (var kv in expectedMap)
            {
                if (mandatory.ContainsKey(kv.Key))
                    continue;

                if (!actualMap.ContainsKey(kv.Key))
                    warnings.Add(kv.Key);
            }

            hr.Passed = true;
            hr.Expected = string.Empty;

            if (warnings.Any())
                hr.Message = WARNING + " Recomenda-se incluir: " + string.Join(", ", warnings);
            else
                hr.Message = "OK";

            return hr;
        }

        public static Dictionary<string, string> ParseDirectiveMap(string header)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var parts = header.Split(';').Select(p => p.Trim()).Where(p => !string.IsNullOrEmpty(p));

            foreach (var p in parts)
            {
                if (p.Contains('='))
                {
                    var sp = p.Split('=', 2);
                    dict[sp[0].Trim()] = sp[1].Trim();
                }
                else dict[p.Trim()] = "true";
            }

            return dict;
        }

        public static Dictionary<string, string> ParseCspDirectives(string s)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var parts = s.Split(';').Select(p => p.Trim()).Where(p => !string.IsNullOrEmpty(p));

            foreach (var p in parts)
            {
                var idx = p.IndexOf(' ');

                if (idx > 0)
                {
                    var name = p[..idx].ToLowerInvariant();
                    var val = p[(idx + 1)..].Trim();
                    map[name] = Regex.Replace(val, @"\s+", " ").Trim();
                }
                else map[p.ToLowerInvariant()] = "";
            }

            return map;
        }

        public static string RenderHtml(List<ReportItem> items, string timestamp)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!doctype html><html><head><meta charset='utf-8'><title>Security Header Report</title>");

            sb.AppendLine(@"
                <style>
                
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
                
                body{
                    font-family:'Inter',system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
                    margin:24px;
                    background:#f7f9fb;
                    color:#0f172a;
                    font-weight:500;
                    font-size:15px;
                    line-height:1.5;
                }

                h2,h3{
                    margin-top:28px;
                }

                table{
                    border-collapse:separate;
                    border-spacing:0;
                    width:100%;
                    background:white;
                    box-shadow:0 2px 8px rgba(0,0,0,0.08);
                    border-radius:8px;
                    overflow:hidden;
                    margin-bottom:24px;
                }

                th{
                    background:#1f3b5c;
                    color:#ffffff;
                    text-align:left;
                    padding:12px;
                    font-size:14px;
                    font-weight:600;
                    letter-spacing:.4px;
                }

                td{
                    padding:10px 12px;
                    border-bottom:1px solid #e5e7eb;
                    vertical-align:top;
                    font-size:14px;
                }

                tr:last-child td{
                    border-bottom:none;
                }

                tr:nth-child(even){
                    background:#f9fbfd;
                }

                .ok{color:#067647;font-weight:800}
                .fail{color:#b42318;font-weight:800}
                .warn{color:#b54708;font-weight:800}
                .missing{color:#912018;font-weight:800}

                .mono{
                    white-space:pre-wrap;
                }

                tr:has(.missing){ background:#fff0f0; }
                tr:has(.fail){ background:#fff5f5; }
                tr:has(.warn){ background:#fffaf0; }

                .legend{
                    background:white;
                    border-radius:8px;
                    padding:14px 18px;
                    box-shadow:0 1px 6px rgba(0,0,0,0.08);
                    margin-bottom:20px;
                }

                .legend ul{
                    margin:6px 0 0 18px;
                }
                </style>
                ");

            sb.AppendLine("</head><body>");
            sb.AppendLine($"<h1>Security Header Report</h1><p>Gerado: {DateTime.Now}</p>");

            foreach (var it in items)
            {
                sb.AppendLine("<hr>");

                sb.AppendLine($"<section><h2>{System.Net.WebUtility.HtmlEncode(it.Url)}</h2>");

                if (!string.IsNullOrEmpty(it.Error))
                {
                    sb.AppendLine($"<p style='color:red'>Erro: {System.Net.WebUtility.HtmlEncode(it.Error)}</p></section>");
                    continue;
                }

                var headersSafe = it.Headers ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                sb.AppendLine("<table><tr><th>Header</th><th>Status</th><th>Valor Atual</th><th>Esperado</th><th>Detalhes</th></tr>");

                var existingHeaders = it.Comparisons.HeaderChecks
                    .ToDictionary(h => h.Name, StringComparer.OrdinalIgnoreCase);

                foreach (var kv in ReferenceHeaders)
                {
                    var headerName = kv.Key;
                    existingHeaders.TryGetValue(headerName, out var h);

                    // Header ausente

                    if (h == null)
                    {
                        string expected = "";

                        if (headerName.Equals("Permissions-Policy", StringComparison.OrdinalIgnoreCase))
                        {
                            var pp = CheckPermissionsPolicy(null);
                            expected = pp.Expected;
                        }
                        else
                        {
                            ReferenceHeaders.TryGetValue(headerName, out expected);
                        }

                        sb.AppendLine($@"
                            <tr>
                            <td>{System.Net.WebUtility.HtmlEncode(headerName)}</td>
                            <td><span class='missing'>⛔</span></td>
                            <td></td>
                            <td class='mono'>{System.Net.WebUtility.HtmlEncode(expected)}</td>
                            <td>Header não configurado</td>
                            </tr>");
                        continue;
                    }

                    // Header presente

                    string expectedValue;

                    if (!string.IsNullOrWhiteSpace(h.Expected))
                        expectedValue = h.Expected;
                    else
                        ReferenceHeaders.TryGetValue(h.Name, out expectedValue);

                    string status =
                        !string.IsNullOrEmpty(h.Message) && h.Message.StartsWith(WARNING)
                        ? "<span class='warn'>⚠️</span>"
                        : h.Passed ? "<span class='ok'>✔️</span>" : "<span class='fail'>❌</span>";

                    sb.AppendLine($@"
                        <tr>
                        <td>{System.Net.WebUtility.HtmlEncode(h.Name)}</td>
                        <td>{status}</td>
                        <td class='mono'>{System.Net.WebUtility.HtmlEncode(h.Actual ?? "(vazio)")}</td>
                        <td class='mono'>{System.Net.WebUtility.HtmlEncode(expectedValue)}</td>
                        <td>{System.Net.WebUtility.HtmlEncode(h.Message ?? "").Replace(WARNING, "")}</td>
                        </tr>");
                }

                sb.AppendLine("</table>");

                sb.AppendLine("<h3>Server exposure</h3>");
                if (it.Comparisons.ServerExposed)
                {
                    sb.AppendLine($"<p class='fail'>Cabeçalhos expõem informações do servidor. Server: {System.Net.WebUtility.HtmlEncode(it.Comparisons.ServerHeader ?? "(vazio)")}; X-Powered-By: {System.Net.WebUtility.HtmlEncode(it.Comparisons.XPoweredBy ?? "(vazio)")}</p>");
                }
                else
                {
                    sb.AppendLine("<p class='ok'>Informações do servidor ocultas (conforme).</p>");
                }

                sb.AppendLine("</section><hr/>");
            }

            // Legenda
            sb.AppendLine(GetLegenda());

            sb.AppendLine("</body></html>");
            return sb.ToString();
        }

        private static string GetLegenda() => @"
                <div class='legend'>
                <strong>Legenda:</strong>
                <ul style='margin-top:8px'>
                    <li><span class='ok'>✔️ Conforme</span>: Configuração correta, nenhuma ação necessária</li>
                    <li><span class='warn'>⚠️ Atenção</span>: Deve ser analisado e, se possível, ajustado para ficar conforme</li>
                    <li><span class='fail'>❌ Não conforme</span>: Erro identificado, deve ser corrigido</li>
                    <li><span class='missing'>⛔ Ausente</span>: Header de segurança ausente, deve ser implementado</li>
                </ul>
                </div>
                ";
    }

    public class ReportItem
    {
        public string Url { get; set; } = "";
        public DateTime TimestampUtc { get; set; }
        public string? Error { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public ComparisonsResult Comparisons { get; set; } = new ComparisonsResult();
    }

    public class ComparisonsResult
    {
        public List<HeaderCheckResult> HeaderChecks { get; set; } = new List<HeaderCheckResult>();
        public bool ServerExposed { get; set; }
        public string? ServerHeader { get; set; }
        public string? XPoweredBy { get; set; }
    }

    public class HeaderCheckResult
    {
        public string Name { get; set; } = "";
        public string? Expected { get; set; }
        public string? Actual { get; set; }
        public bool Passed { get; set; }
        public string? Message { get; set; }
    }

    public class ParsedCookie
    {
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public bool Secure { get; set; }
        public bool HttpOnly { get; set; }
        public string? SameSite { get; set; }
        public string Raw { get; set; } = "";
    }

    public static class Scanner
    {
        public static async Task<string> RunScan(List<string> urls)
        {
            Directory.CreateDirectory("Reports");
            var reportItems = new List<ReportItem>();

            foreach (var url in urls)
                reportItems.Add(await SecurityAnalyzer.AnalyzeUrl(url));

            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var outPath = Path.Combine("Reports", $"report_{timestamp}.html");
            File.WriteAllText(outPath, SecurityAnalyzer.RenderHtml(reportItems, timestamp));

            return outPath;
        }
    }
}
