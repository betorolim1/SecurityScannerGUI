using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
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
            ["Content-Security-Policy"] = "",
            ["X-Content-Type-Options"] = "nosniff",
            ["Referrer-Policy"] = "no-referrer",
            ["Permissions-Policy"] = "",
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

                // Integração CSP Evaluator (Google) 
                await ApplyCspEvaluatorAsync(headers, item);
            }
            catch (Exception ex)
            {
                item.Error = ex.Message;
            }
            return item;
        }

        private static async Task ApplyCspEvaluatorAsync(
            Dictionary<string, string> headers,
            ReportItem item)
        {
            if (!headers.TryGetValue("Content-Security-Policy", out var cspValue))
                return;

            var analysis = await AnalyzeCspAsync(cspValue);

            var cspResult = item.Comparisons.HeaderChecks
                .FirstOrDefault(h => h.Name.Equals("Content-Security-Policy", StringComparison.OrdinalIgnoreCase));

            if (cspResult == null || analysis == null)
                return;

            if (analysis.Risk != CspRisk.Secure)
                cspResult.Passed = false;

            string riskMessage = analysis.Risk switch
            {
                CspRisk.Secure => "",
                CspRisk.Weak => "Política fraca, ainda é possível injeção de scripts.",
                CspRisk.Bypassable => "Política muito fraca, a injeção de scripts não é efetivamente bloqueada.",
                _ => ""
            };

            if (!string.IsNullOrWhiteSpace(riskMessage))
            {
                if (string.IsNullOrEmpty(cspResult.Message))
                    cspResult.Message = riskMessage;
                else
                    cspResult.Message += " | " + riskMessage;
            }

            var recommendations = analysis.Findings
                .Where(f => f.Severity >= 30 && !string.IsNullOrWhiteSpace(f.Description))
                .Select(f => f.Description!.Trim())
                .Distinct()
                .ToList();

            if (recommendations.Any())
            {
                var evaluatorBlock =
                    "<div class='csp-evaluator'>" +
                    "<strong>CSP Evaluator:</strong><br>" +
                    string.Join("<br>", recommendations) +
                    "</div>";

                if (string.IsNullOrWhiteSpace(cspResult.Expected))
                    cspResult.Expected = evaluatorBlock;
                else
                    cspResult.Expected += "<br><br>" + evaluatorBlock;
            }
        }

        public static ComparisonsResult CompareWithReference(Dictionary<string, string> headers)
        {
            var result = new ComparisonsResult();
            var headerResults = new List<HeaderCheckResult>();

            foreach (var kv in ReferenceHeaders)
            {
                headers.TryGetValue(kv.Key, out var actual);

                var expected = kv.Value;
                var hr = new HeaderCheckResult { Name = kv.Key, Expected = expected, Actual = actual };

                if (string.Equals(kv.Key, "Strict-Transport-Security", StringComparison.OrdinalIgnoreCase))
                {
                    hr = CheckHsts(expected, actual);
                }
                else if (string.Equals(kv.Key, "Content-Security-Policy", StringComparison.OrdinalIgnoreCase))
                {
                    hr = CheckCspBaseline(actual);
                    headerResults.Add(hr);
                    continue;
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
                Actual = actual
            };

            if (string.IsNullOrEmpty(actual))
            {
                hr.Passed = false;
                hr.Message = "header ausente";

                hr.Expected =
                    "<div class='security-baseline'>" +
                    "<strong>Diretivas obrigatórias:</strong>" +
                    "<ul><li>" + string.Join("</li><li>", mandatoryDisabled.Select(d => $"{d}=()")) + "</li></ul>" +
                    "</div>";

                return hr;
            }

            var policy = ParsePermissionsPolicy(actual);

            var missingMandatory = mandatoryDisabled
                .Where(d => !policy.ContainsKey(d))
                .ToList();

            if (missingMandatory.Any())
            {
                hr.Passed = false;

                var list = missingMandatory.Select(d => $"{d}=()").ToList();

                hr.Expected =
                    "<div class='security-baseline'>" +
                    "<strong>Diretivas obrigatórias:</strong>" +
                    "<ul><li>" + string.Join("</li><li>", list) + "</li></ul>" +
                    "</div>";

                hr.Message = "Diretivas mínimas ausentes";

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
            hr.Expected = "";

            if (warnings.Any())
            {
                hr.Message = WARNING +
                    " Diretivas sensíveis ativas — validar necessidade funcional: " +
                    string.Join(", ", warnings);
            }
            else
            {
                hr.Message = "";
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

        public static Dictionary<string, List<string>> ParseCspDirectives(string header)
        {
            var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            var directives = header.Split(';', StringSplitOptions.RemoveEmptyEntries);

            foreach (var directive in directives)
            {
                var parts = directive.Trim()
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries);

                if (parts.Length == 0)
                    continue;

                var name = parts[0].ToLowerInvariant();
                var values = parts.Skip(1).Select(v => v.Trim()).ToList();

                map[name] = values;
            }

            return map;
        }

        public static HeaderCheckResult CheckCspBaseline(string actual)
        {
            var hr = new HeaderCheckResult
            {
                Name = "Content-Security-Policy",
                Actual = actual
            };

            // HEADER AUSENTE
            if (string.IsNullOrWhiteSpace(actual))
            {
                hr.Passed = false;

                var allDirectives = CspBaseline.MandatoryValues
                    .Select(k => $"{k.Key} {string.Join(" ", k.Value)}")
                    .ToList();

                hr.Expected =
                    "<div class='security-baseline'>" +
                    "<strong>Diretivas obrigatórias:</strong>" +
                    "<ul><li>" + string.Join("</li><li>", allDirectives) + "</li></ul>" +
                    "</div>";

                hr.Message = "header ausente";
                return hr;
            }


            var map = ParseCspDirectives(actual);

            var missingMandatory = new List<string>();
            var wrongValue = new List<string>();

            foreach (var directive in CspBaseline.MandatoryDirectives)
            {
                if (!map.ContainsKey(directive))
                {
                    missingMandatory.Add(directive);
                    continue;
                }

                if (CspBaseline.MandatoryValues.TryGetValue(directive, out var expectedValues))
                {
                    var values = map[directive];

                    if (!values.Any(v => expectedValues.Contains(v, StringComparer.OrdinalIgnoreCase)))
                        wrongValue.Add(directive);
                }
            }

            var missingRecommended = CspBaseline.RecommendedDirectives
                .Where(d => !map.ContainsKey(d))
                .ToList();

            // NÃO CONFORME
            if (missingMandatory.Any() || wrongValue.Any())
            {
                hr.Passed = false;

                var expectedParts = new List<string>();

                // faltantes
                foreach (var m in missingMandatory)
                    expectedParts.Add($"{m} {string.Join(" ", CspBaseline.MandatoryValues[m])}");

                // valor inseguro (precisa corrigir)
                foreach (var w in wrongValue)
                    expectedParts.Add($"{w} {string.Join(" ", CspBaseline.MandatoryValues[w])}");

                hr.Expected =
                 "<div class='security-baseline'>" +
                 "<strong>Diretivas obrigatórias:</strong>" +
                 "<ul><li>" + string.Join("</li><li>", expectedParts) + "</li></ul>" +
                 "</div>";


                var parts = new List<string>();

                if (wrongValue.Any())
                    parts.Add("Diretivas com valor inseguro: " + string.Join(", ", wrongValue));

                if (missingRecommended.Any())
                    parts.Add("Recomendadas ausentes: " + string.Join(", ", missingRecommended));

                hr.Message = string.Join(" | ", parts);
                return hr;
            }

            // CONFORME
            hr.Passed = true;
            hr.Expected = string.Empty;

            if (missingRecommended.Any())
                hr.Message = WARNING + " Recomenda-se incluir: " + string.Join(", ", missingRecommended);
            else
                hr.Message = "";

            return hr;
        }

        public static async Task<CspAnalysisResult?> AnalyzeCspAsync(string? cspHeader)
        {
            if (string.IsNullOrWhiteSpace(cspHeader))
                return null;

            var json = await RunCspEvaluator(cspHeader);

            var findings = JsonSerializer.Deserialize<List<CspFinding>>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();

            return new CspAnalysisResult
            {
                Risk = Classify(findings),
                Findings = findings
            };
        }

        public static async Task<string> RunCspEvaluator(string csp)
        {
            var nodePath = Path.Combine(AppContext.BaseDirectory, "tools", "csp", "node", "node.exe");
            var scriptPath = Path.Combine(AppContext.BaseDirectory, "tools", "csp", "run.js");

            var psi = new ProcessStartInfo
            {
                FileName = nodePath,
                Arguments = $"\"{scriptPath}\" \"{csp.Replace("\"", "\\\"")}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };

            using var process = Process.Start(psi);

            string output = await process.StandardOutput.ReadToEndAsync();
            string error = await process.StandardError.ReadToEndAsync();

            await process.WaitForExitAsync();

            if (process.ExitCode != 0)
                throw new Exception($"CSP Engine error: {error}");

            return output;
        }

        public static CspRisk Classify(IEnumerable<CspFinding> findings)
        {
            if (findings == null || !findings.Any())
                return CspRisk.Secure;

            int max = findings.Max(f => f.Severity);

            if (max >= 50)
                return CspRisk.Bypassable;

            if (max >= 30 || max >= 10)
                return CspRisk.Weak;

            return CspRisk.Secure;
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

                .csp-evaluator{
                    background:#f0f7ff;
                    border-left:4px solid #1d4ed8;
                    padding:8px;
                    border-radius:6px;
                    font-size:13px;
                }

                .security-baseline{
                    background:#fff5f5;
                    border-left:4px solid #b42318;
                    padding:8px;
                    border-radius:6px;
                    font-size:13px;
                }

                .security-baseline ul{
                    margin:6px 0 0 18px;
                    padding:0;
                }

                .security-baseline li{
                    margin-bottom:2px;
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

                    bool isRichHtml =
                        headerName.Equals("Content-Security-Policy", StringComparison.OrdinalIgnoreCase) ||
                        headerName.Equals("Permissions-Policy", StringComparison.OrdinalIgnoreCase);

                    string expectedRendered = isRichHtml
                        ? (expectedValue ?? "")
                        : System.Net.WebUtility.HtmlEncode(expectedValue ?? "");

                    sb.AppendLine($@"
                    <tr>
                    <td>{System.Net.WebUtility.HtmlEncode(h.Name)}</td>
                    <td>{status}</td>
                    <td class='mono'>{System.Net.WebUtility.HtmlEncode(h.Actual ?? "(vazio)")}</td>
                    <td class='mono'>{expectedRendered}</td>
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

    public class CspFinding
    {
        public int Type { get; set; }
        public string? Description { get; set; }
        public int Severity { get; set; }
        public string? Directive { get; set; }
        public string? Value { get; set; }
    }

    public enum CspRisk
    {
        Secure,
        Weak,
        Bypassable
    }

    public class CspAnalysisResult
    {
        public CspRisk Risk { get; set; }
        public List<CspFinding> Findings { get; set; } = new();
    }

    public static class CspBaseline
    {
        public static readonly string[] MandatoryDirectives =
        {
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "object-src",
        "frame-ancestors",
        "font-src",
        "form-action",
        "frame-src",
        "base-uri",
        "require-trusted-types-for"
    };

        public static readonly Dictionary<string, string[]> MandatoryValues = new(StringComparer.OrdinalIgnoreCase)
        {
            ["default-src"] = new[] { "'self'" },
            ["script-src"] = new[] { "'self'" },
            ["style-src"] = new[] { "'self'" },
            ["img-src"] = new[] { "'self'", "data:" },
            ["font-src"] = new[] { "'self'" },
            ["frame-src"] = new[] { "'self'" },
            ["object-src"] = new[] { "'none'" },
            ["frame-ancestors"] = new[] { "'none'" },
            ["base-uri"] = new[] { "'self'" },
            ["form-action"] = new[] { "'self'" },
            ["require-trusted-types-for"] = new[] { "'script'" }
        };

        public static readonly string[] RecommendedDirectives = Array.Empty<string>();
    }
}
