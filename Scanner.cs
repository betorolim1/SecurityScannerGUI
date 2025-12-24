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
            sb.AppendLine("<style>body{font-family:Arial,Helvetica,sans-serif;margin:20px} table{border-collapse:collapse;width:100%;margin-bottom:18px} th,td{border:1px solid #ddd;padding:8px} th{background:#f4f4f4} .ok{color:green;font-weight:700}.fail{color:red;font-weight:700}.mono{font-family:monospace;white-space:pre-wrap}</style>");
            sb.AppendLine("</head><body>");
            sb.AppendLine($"<h1>Security Header Report</h1><p>Gerado: {DateTime.Now}</p>");

            foreach (var it in items)
            {
                sb.AppendLine("<br>");

                sb.AppendLine("<hr>");

                sb.AppendLine($"<section><h2>{System.Net.WebUtility.HtmlEncode(it.Url)}</h2>");

                sb.AppendLine("<hr>");

                sb.AppendLine("<br>");

                if (!string.IsNullOrEmpty(it.Error))
                {
                    sb.AppendLine($"<p style='color:red'>Erro: {System.Net.WebUtility.HtmlEncode(it.Error)}</p></section>");
                    continue;
                }

                var headersSafe = it.Headers ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                var missingHeaders = ReferenceHeaders.Keys
                    .Where(refKey => !headersSafe.ContainsKey(refKey))
                    .ToList();

                if (missingHeaders.Any())
                {
                    sb.AppendLine("<div style='background:#fff3cd;border:1px solid #ffeeba;padding:10px;margin-bottom:15px;border-radius:5px;'>");
                    sb.AppendLine("<strong>⚠️ Headers de segurança ausentes:</strong><br>");
                    sb.AppendLine(string.Join(", ", missingHeaders.Select(h => System.Net.WebUtility.HtmlEncode(h))));
                    sb.AppendLine("</div>");
                }

                sb.AppendLine("<h3>Headers</h3>");
                sb.AppendLine("<table><tr><th>Header</th><th>Status</th><th>Valor Atual</th><th>Esperado</th><th>Detalhes</th></tr>");

                foreach (var h in it.Comparisons.HeaderChecks)
                {
                    string status =
                        !string.IsNullOrEmpty(h.Message) && h.Message.StartsWith(WARNING)
                        ? "<span class='warn'>⚠️</span>"
                        : h.Passed ? "<span class='ok'>✔️</span>" : "<span class='fail'>❌</span>";

                    sb.AppendLine($"<tr><td>{System.Net.WebUtility.HtmlEncode(h.Name)}</td><td>{status}</td><td class='mono'>{System.Net.WebUtility.HtmlEncode(h.Actual ?? "(vazio)")}</td><td class='mono'>{System.Net.WebUtility.HtmlEncode(h.Expected ?? "")}</td><td>{System.Net.WebUtility.HtmlEncode(h.Message ?? "").Replace(WARNING, "")}</td></tr>");
                }

                sb.AppendLine("</table>");

                sb.AppendLine("<h3>Server exposure</h3>");
                if (it.Comparisons.ServerExposed)
                {
                    sb.AppendLine($"<p class='fail'>Cabeçalhos expõem informações do servidor. Server: {System.Net.WebUtility.HtmlEncode(it.Comparisons.ServerHeader ?? "(vazio)")}; X-Powered-By: {System.Net.WebUtility.HtmlEncode(it.Comparisons.XPoweredBy ?? "(vazio)")}</p>");
                }
                else
                {
                    sb.AppendLine("<p class='ok'>Informações do servidor ocultas (bom).</p>");
                }

                sb.AppendLine("</section><hr/>");
            }

            sb.AppendLine(@"
                <div style='background:#eef3f7;
                            border:1px solid #cfd8e3;
                            padding:12px;
                            margin:15px 0;
                            border-radius:6px;'>

                <strong>Legenda:</strong>
                <ul style='margin-top:8px'>
                    <li><span class='ok'>✔️ Conforme</span>: Configuração correta, nenhuma ação necessária</li>
                    <li><span class='warn'>⚠️ Atenção</span>: Deve ser analisado e, se possível, ajustado para ficar conforme</li>
                    <li><span class='fail'>❌ Não conforme</span>: Erro identificado, deve ser corrigido</li>
                </ul>
                </div>
                ");

            sb.AppendLine("</body></html>");
            return sb.ToString();
        }
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
