using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection.PortableExecutable;
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
            ["Cross-Origin-Embedder-Policy"] = "require-corp OR credentialless",
            ["Cache-Control"] = ""
        };

        static readonly HashSet<string> ApiOnlyHeaders = new(StringComparer.OrdinalIgnoreCase)
        {
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Cache-Control",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Referrer-Policy",
            "Cross-Origin-Resource-Policy"
        };

        static readonly string WARNING = "!warning!";

        public static async Task<ReportItem> AnalyzeUrl(string url, bool isApi = false)
        {
            url = TreatURL(url);

            var item = new ReportItem
            {
                Url = url,
                IsApi = isApi,
                TimestampUtc = DateTime.UtcNow
            };

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                using var res = await _http.SendAsync(req);

                var headers = GetHeaders(res);

                item.Headers = headers;

                item.Comparisons = CompareWithReference(headers, isApi);

                if (!isApi)
                    await ApplyCspEvaluatorAsync(headers, item);

                var cookies = GetCookie(res);

                item.Cookies = cookies;
                item.CookieChecks = AnalyzeCookies(cookies);
            }
            catch (Exception ex)
            {
                item.Error = ex.Message;
            }
            return item;
        }

        private static List<ParsedCookie> GetCookie(HttpResponseMessage res)
        {
            var cookies = new List<ParsedCookie>();
            if (res.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var raw in setCookies)
                {
                    cookies.Add(ParseCookie(raw));
                }
            }
            return cookies;
        }

        private static ParsedCookie ParseCookie(string raw)
        {
            var parts = raw.Split(';', StringSplitOptions.RemoveEmptyEntries)
                           .Select(p => p.Trim())
                           .ToList();

            var first = parts[0].Split('=', 2);

            var cookie = new ParsedCookie
            {
                Name = first[0],
                Value = first.Length > 1 ? first[1] : "",
                Raw = raw
            };

            foreach (var p in parts.Skip(1))
            {
                if (p.Equals("Secure", StringComparison.OrdinalIgnoreCase))
                    cookie.Secure = true;

                if (p.Equals("HttpOnly", StringComparison.OrdinalIgnoreCase))
                    cookie.HttpOnly = true;

                if (p.StartsWith("SameSite", StringComparison.OrdinalIgnoreCase))
                {
                    var sp = p.Split('=');
                    if (sp.Length == 2)
                        cookie.SameSite = sp[1];
                }
            }

            return cookie;
        }

        private static List<CookieCheckResult> AnalyzeCookies(List<ParsedCookie> cookies)
        {
            var results = new List<CookieCheckResult>();

            foreach (var c in cookies)
            {
                var r = new CookieCheckResult
                {
                    Name = c.Name,
                    Secure = c.Secure,
                    HttpOnly = c.HttpOnly,
                    SameSite = c.SameSite
                };

                if (c.Name.Equals("Abacaxi", StringComparison.OrdinalIgnoreCase))
                {
                    r.Ignored = true;
                    r.Passed = true;
                    r.Message = "Cookie do F5 (não gerenciável)";
                    results.Add(r);
                    continue;
                }

                // Cookies TS* do F5 (bot defense / persistence)
                if (Regex.IsMatch(c.Name, @"^TS[0-9a-fA-F]+$", RegexOptions.IgnoreCase))
                {
                    r.Ignored = true;
                    r.Passed = true;
                    r.Message = "Cookie do F5 (não gerenciável)";
                    results.Add(r);
                    continue;
                }

                var problems = new List<string>();

                if (!c.Secure)
                    problems.Add("Secure ausente");

                if (!c.HttpOnly)
                    problems.Add("HttpOnly ausente");

                if (string.IsNullOrEmpty(c.SameSite))
                    problems.Add("SameSite ausente");

                r.Passed = problems.Count == 0;
                r.Message = string.Join("; ", problems);

                results.Add(r);
            }

            return results;
        }

        private static Dictionary<string, string> GetHeaders(HttpResponseMessage res)
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var h in res.Headers)
                headers[h.Key] = string.Join("; ", h.Value);

            foreach (var h in res.Content.Headers)
                headers[h.Key] = string.Join("; ", h.Value);

            return headers;
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

            bool hasUnsafeInline = cspValue?.Contains("unsafe-inline", StringComparison.OrdinalIgnoreCase) == true;

            if (hasUnsafeInline)
            {
                cspResult.Passed = false;
            }

            string selfMessage = WARNING + "O uso de 'self' em script-src amplia a superfície de ataque caso o domínio hospede JSONP, AngularJS legado ou conteúdo enviado por usuários. Sempre que possível, utilize uma política mais restritiva baseada em origens específicas, hashes ou nonces.";

            bool hasSelfWarning =
                analysis.Findings.Any(f =>
                    f.Description?.Contains("'self'", StringComparison.OrdinalIgnoreCase) == true);

            if (hasSelfWarning && cspResult.Passed)
            {
                cspResult.Message = selfMessage;
            }
            else if (analysis.Risk != CspRisk.Secure)
            {
                cspResult.Passed = false;

                string riskMessage = analysis.Risk switch
                {
                    CspRisk.Secure => "",
                    CspRisk.Weak => "A injeção de scripts não é efetivamente bloqueada.",
                    CspRisk.Bypassable => "A injeção de scripts não é efetivamente bloqueada.",
                    _ => ""
                };

                if (hasSelfWarning)
                {
                    cspResult.Message = riskMessage + "\n\n" + selfMessage;
                }
                else if (!string.IsNullOrWhiteSpace(riskMessage))
                {
                    cspResult.Message = riskMessage;
                }
            }

            var recommendations = new List<string>();

            foreach (var finding in analysis.Findings)
            {
                if (string.IsNullOrWhiteSpace(finding.Description))
                    continue;

                var desc = finding.Description.Trim();

                if (desc.Contains("'self' can be problematic", StringComparison.OrdinalIgnoreCase) &&
                    desc.Contains("No bypass found", StringComparison.OrdinalIgnoreCase))
                {
                    recommendations.Add(
                        WARNING +
                        " CSP Evaluator: uso de 'self'. Validar se o domínio não hospeda JSONP, AngularJS legado ou arquivos enviados por usuários.");
                }
                else if (finding.Severity >= 30)
                {
                    recommendations.Add(desc);
                }
            }

            if (hasUnsafeInline)
            {
                string unsafeInlineMsg = "unsafe-inline não é aceito. Remova 'unsafe-inline' de todas as diretivas.";

                if (!string.IsNullOrEmpty(cspResult.Message))
                    cspResult.Message += "\n\n" + unsafeInlineMsg;
                else
                    cspResult.Message = unsafeInlineMsg;
            }

            recommendations = recommendations
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

        private static string TreatURL(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                url = $"https://{url.TrimStart('/')}";
            }

            return url;
        }

        private static List<string> ParseUrlList(string input)
        {
            return input
                .Split(new[] { '\r', '\n', ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(u => u.Trim())
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public static ComparisonsResult CompareWithReference(Dictionary<string, string> headers, bool isApi = false)
        {
            var result = new ComparisonsResult();
            var headerResults = new List<HeaderCheckResult>();

            foreach (var kv in ReferenceHeaders)
            {
                // No modo API, pular headers que não se aplicam
                if (isApi && !ApiOnlyHeaders.Contains(kv.Key))
                    continue;

                headers.TryGetValue(kv.Key, out var actual);

                var expected = kv.Value;
                var hr = new HeaderCheckResult { Name = kv.Key, Expected = expected, Actual = actual };

                if (string.Equals(kv.Key, "Strict-Transport-Security", StringComparison.OrdinalIgnoreCase))
                {
                    hr = CheckHsts(expected, actual);
                }
                else if (string.Equals(kv.Key, "Content-Security-Policy", StringComparison.OrdinalIgnoreCase))
                {
                    if (isApi)
                    {
                        hr = CheckCspApi(actual);
                    }
                    else
                    {
                        hr = CheckCspBaseline(actual);
                    }

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
                else if (string.Equals(kv.Key, "Cross-Origin-Resource-Policy", StringComparison.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrEmpty(actual))
                    {
                        hr.Passed = false;
                        hr.Message = "header ausente";
                    }
                    else if (Normalize(actual) == "same-origin")
                    {
                        hr.Passed = true;
                        hr.Message = string.Empty;
                    }
                    else if (isApi && Normalize(actual) == "cross-origin")
                    {
                        hr.Passed = true;
                        hr.Message = WARNING + " Recurso acessível por qualquer origem — validar se a API expõe dados públicos/abertos.";
                    }
                    else if (Normalize(actual) == "same-site")
                    {
                        hr.Passed = false;
                        hr.Message = WARNING + " Valor permitido, mas menos seguro que same-origin";
                    }
                    else
                    {
                        hr.Passed = false;
                        hr.Message = "valor diferente";
                    }

                    headerResults.Add(hr);
                    continue;
                }
                else if (string.Equals(kv.Key, "X-Frame-Options", StringComparison.OrdinalIgnoreCase))
                {
                    if (isApi)
                        hr.Expected = "DENY";

                    if (string.IsNullOrEmpty(actual))
                    {
                        hr.Passed = false;
                        hr.Message = "header ausente";
                    }
                    else if (isApi)
                    {
                        hr.Passed = Normalize(actual) == "deny";
                        if (!hr.Passed)
                            hr.Message = "Para APIs, recomenda-se DENY em vez de SAMEORIGIN";
                    }
                    else
                    {
                        hr.Passed = Normalize(actual) == Normalize(expected);
                        if (!hr.Passed) hr.Message = "valor diferente";
                    }

                    headerResults.Add(hr);
                    continue;
                }
                else if (string.Equals(kv.Key, "Cache-Control", StringComparison.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrEmpty(actual))
                    {
                        hr.Passed = false;
                        hr.Message = "header ausente";
                    }
                    else
                    {
                        var norm = Normalize(actual);

                        bool hasNoStore = norm.Contains("no-store");
                        bool hasMaxAge = norm.Contains("max-age=");

                        if (hasNoStore || hasMaxAge)
                        {
                            hr.Passed = true;
                            hr.Message = string.Empty;
                        }
                        else
                        {
                            hr.Passed = false;
                            hr.Message = WARNING + " Cache-Control presente, mas sem no-store nem max-age — o tempo de expiração do cache não está explícito.";
                        }
                    }

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

        public static HeaderCheckResult CheckCspApi(string? actual)
        {
            var hr = new HeaderCheckResult
            {
                Name = "Content-Security-Policy",
                Expected = "frame-ancestors 'none'",
                Actual = actual
            };

            if (string.IsNullOrWhiteSpace(actual))
            {
                hr.Passed = false;
                hr.Message = "header ausente";
                return hr;
            }

            var map = ParseCspDirectives(actual);

            if (!map.ContainsKey("frame-ancestors"))
            {
                hr.Passed = false;
                hr.Message = "frame-ancestors ausente";
                return hr;
            }

            var values = map["frame-ancestors"];
            hr.Passed = values.Contains("'none'", StringComparer.OrdinalIgnoreCase);

            if (!hr.Passed)
                hr.Message = "Para APIs, frame-ancestors deve ser 'none'";

            return hr;
        }

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

            var sensitiveGov = new[]
            {
                "camera",
                "microphone",
                "geolocation",
                "fullscreen"
            };

            var warnings = sensitiveGov
                .Where(d => policy.ContainsKey(d) && policy[d] == "*")
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

            if (missingMandatory.Any() || wrongValue.Any())
            {
                hr.Passed = false;

                var expectedParts = new List<string>();

                foreach (var m in missingMandatory)
                    expectedParts.Add($"{m} {string.Join(" ", CspBaseline.MandatoryValues[m])}");

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

        // ═══════════════════════════════════════════════════════
        // RENDER HTML — Relatório visual redesenhado
        // ═══════════════════════════════════════════════════════

        public static string RenderHtml(List<ReportItem> items, string timestamp)
        {
            // Contadores globais
            int totalOk = 0, totalFail = 0, totalWarn = 0, totalMissing = 0;
            foreach (var it in items)
            {
                if (it.Error != null) continue;

                // Headers
                foreach (var h in it.Comparisons.HeaderChecks)
                {
                    if (string.IsNullOrEmpty(h.Actual) && !h.Passed) totalMissing++;
                    else if (!string.IsNullOrEmpty(h.Message) && h.Message.StartsWith(WARNING)) totalWarn++;
                    else if (h.Passed) totalOk++;
                    else totalFail++;
                }

                // Server Exposure (1 verificação por URL)
                if (it.Comparisons.ServerExposed)
                    totalFail++;
                else
                    totalOk++;

                // Cookies (1 verificação por cookie)
                if (it.CookieChecks != null)
                {
                    foreach (var c in it.CookieChecks)
                    {
                        if (c.Ignored) continue;

                        if (c.Secure) totalOk++; else totalFail++;
                        if (c.HttpOnly) totalOk++; else totalFail++;
                        if (!string.IsNullOrEmpty(c.SameSite)) totalOk++; else totalFail++;
                    }
                }
            }
            int totalChecks = totalOk + totalFail + totalWarn + totalMissing;

            // Determinar os headers de referência por item (para iteração na tabela)
            // Usa o set filtrado se for API
            Dictionary<string, string> GetReferenceHeadersFor(ReportItem it)
            {
                if (!it.IsApi) return ReferenceHeaders;

                return ReferenceHeaders
                    .Where(kv => ApiOnlyHeaders.Contains(kv.Key))
                    .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);
            }

            var sb = new StringBuilder();
            sb.AppendLine("<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'>");
            sb.AppendLine("<meta name='viewport' content='width=device-width, initial-scale=1'>");
            sb.AppendLine("<title>Security Header Report</title>");

            // ── CSS ──
            sb.AppendLine("<style>");
            sb.AppendLine(@"
:root {
    --bg-body: #0f1117;
    --bg-card: #1a1d28;
    --bg-card-alt: #1f2233;
    --bg-header: #12131c;
    --bg-table-head: #242840;
    --bg-table-row-even: #16181f;
    --bg-input: #282a36;
    --text-primary: #e6e8f0;
    --text-secondary: #8c91a5;
    --text-muted: #5a5f75;
    --green: #2ecc71;
    --green-dim: rgba(46,204,113,0.12);
    --red: #e74c3c;
    --red-dim: rgba(231,76,60,0.10);
    --orange: #f39c12;
    --orange-dim: rgba(243,156,18,0.10);
    --blue: #3b82f6;
    --blue-dim: rgba(59,130,246,0.10);
    --purple: #a855f7;
    --purple-dim: rgba(168,85,247,0.12);
    --border: #2a2d3e;
    --radius: 10px;
    --radius-sm: 6px;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg-body);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 0;
    font-size: 14px;
}

/* ── HEADER PRINCIPAL ── */
.report-header {
    background: linear-gradient(135deg, #12131c 0%, #1a1d28 50%, #12131c 100%);
    border-bottom: 1px solid var(--border);
    padding: 40px 48px;
}

.report-header h1 {
    font-size: 28px;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 4px;
    letter-spacing: -0.5px;
}

.report-header h1 .shield { color: var(--green); margin-right: 10px; }

.report-header .meta {
    color: var(--text-secondary);
    font-size: 13px;
    margin-top: 6px;
}

/* ── RESUMO GLOBAL ── */
.summary-bar {
    display: flex;
    gap: 16px;
    padding: 24px 48px;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
}

.summary-card {
    flex: 1;
    min-width: 140px;
    background: var(--bg-card-alt);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 20px;
    text-align: center;
}

.summary-card .number {
    font-size: 32px;
    font-weight: 700;
    line-height: 1;
}

.summary-card .label {
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-top: 6px;
}

.summary-card.ok .number { color: var(--green); }
.summary-card.fail .number { color: var(--red); }
.summary-card.warn .number { color: var(--orange); }
.summary-card.missing .number { color: var(--red); }
.summary-card.total .number { color: var(--blue); }

/* ── CONTEÚDO ── */
.content { padding: 32px 48px; }

/* ── URL SECTION ── */
.url-section {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 32px;
    overflow: hidden;
}

.url-header {
    background: var(--bg-header);
    padding: 18px 24px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 12px;
}

.url-header h2 {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
    word-break: break-all;
    font-family: 'Consolas', 'Courier New', monospace;
}

.url-header .url-icon {
    font-size: 20px;
    flex-shrink: 0;
}

.url-body { padding: 24px; }

.error-box {
    background: var(--red-dim);
    border: 1px solid rgba(231,76,60,0.3);
    border-radius: var(--radius-sm);
    padding: 14px 18px;
    color: var(--red);
    font-weight: 500;
}

/* ── BADGE TIPO (Website / API) ── */
.badge-type {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    white-space: nowrap;
    margin-left: auto;
}

.badge-type-website { background: var(--blue-dim); color: var(--blue); }
.badge-type-api { background: var(--purple-dim); color: var(--purple); }

/* ── TABELAS ── */
table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    margin-bottom: 20px;
}

thead th {
    background: var(--bg-table-head);
    color: var(--text-secondary);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 12px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
}

tbody td {
    padding: 12px 14px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    font-size: 13px;
}

tbody tr:last-child td { border-bottom: none; }
tbody tr:nth-child(even) { background: var(--bg-table-row-even); }

td.mono {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    word-break: break-all;
    color: var(--text-secondary);
}

/* ── BADGES DE STATUS ── */
.badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
}

.badge-ok { background: var(--green-dim); color: var(--green); }
.badge-fail { background: var(--red-dim); color: var(--red); }
.badge-warn { background: var(--orange-dim); color: var(--orange); }
.badge-missing { background: var(--red-dim); color: var(--red); }

/* ── SUB-SEÇÕES (cookies, server) ── */
.sub-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.6px;
    margin: 24px 0 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
}

.server-ok {
    background: var(--green-dim);
    border: 1px solid rgba(46,204,113,0.25);
    border-radius: var(--radius-sm);
    padding: 12px 16px;
    color: var(--green);
    font-weight: 500;
    font-size: 13px;
}

.server-exposed {
    background: var(--red-dim);
    border: 1px solid rgba(231,76,60,0.25);
    border-radius: var(--radius-sm);
    padding: 12px 16px;
    color: var(--red);
    font-weight: 500;
    font-size: 13px;
}

.no-cookies {
    color: var(--green);
    font-weight: 500;
    font-size: 13px;
    padding: 8px 0;
}

/* ── LEGENDA ── */
.legend-section {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 24px;
    margin-top: 16px;
}

.legend-section h3 {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 12px;
    color: var(--text-secondary);
}

.legend-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 8px;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 13px;
    color: var(--text-secondary);
}

/* ── BLOCOS CSP/BASELINE ── */
.csp-evaluator {
    background: var(--blue-dim);
    border-left: 3px solid var(--blue);
    padding: 10px 14px;
    border-radius: var(--radius-sm);
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 6px;
}

.csp-evaluator strong { color: var(--blue); }

.security-baseline {
    background: var(--red-dim);
    border-left: 3px solid var(--red);
    padding: 10px 14px;
    border-radius: var(--radius-sm);
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 6px;
}

.security-baseline strong { color: var(--red); }
.security-baseline ul { margin: 6px 0 0 18px; padding: 0; }
.security-baseline li { margin-bottom: 2px; }

/* ── FOOTER ── */
.report-footer {
    text-align: center;
    padding: 24px;
    color: var(--text-muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
    margin-top: 16px;
}

/* ── PRINT ── */
@media print {
    body { background: white; color: #111; font-size: 11px; padding: 12px; }
    .report-header { background: #f5f5f5; padding: 20px; }
    .report-header h1 { color: #111; font-size: 20px; }
    .summary-bar { background: #fafafa; padding: 12px; }
    .summary-card { background: white; border: 1px solid #ddd; }
    .summary-card .number { font-size: 24px; }
    .url-section { border: 1px solid #ddd; }
    .url-header { background: #f0f0f0; }
    .url-header h2 { color: #111; }
    table { border: 1px solid #ccc; }
    thead th { background: #e8e8e8; color: #333; }
    tbody td { border-bottom: 1px solid #eee; }
    .badge-ok { background: #e8f5e9; color: #2e7d32; }
    .badge-fail { background: #ffebee; color: #c62828; }
    .badge-warn { background: #fff8e1; color: #f57f17; }
    .badge-missing { background: #ffebee; color: #c62828; }
    .badge-type-website { background: #e3f2fd; color: #1565c0; }
    .badge-type-api { background: #f3e5f5; color: #7b1fa2; }
    .content { padding: 12px 0; }
}

.badge-ignored { background: rgba(100,104,120,0.15); color: #8c91a5; }

tr.row-ignored td { opacity: 0.5; }

/* ── TOOLTIP INFO ── */
.info-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    font-size: 13px;
    font-weight: 400;
    border-radius: 50%;
    background: rgba(255,255,255,0.08);
    color: var(--text-muted);
    cursor: help;
    position: relative;
    margin-left: 4px;
    vertical-align: middle;
}

.info-icon:hover { background: rgba(255,255,255,0.15); color: var(--text-secondary); }

.info-icon .info-tip {
    visibility: hidden;
    opacity: 0;
    position: absolute;
    bottom: calc(100% + 8px);
    left: 50%;
    transform: translateX(-50%);
    background: #2a2d3e;
    color: var(--text-primary);
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 400;
    white-space: nowrap;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    border: 1px solid var(--border);
    transition: opacity 0.2s;
    z-index: 10;
    pointer-events: none;
}

td.details {
    max-width: 500px;
    white-space: normal;
    word-break: break-word;
    overflow-wrap: anywhere;
}

.info-icon:hover .info-tip { visibility: visible; opacity: 1; }
            ");
            sb.AppendLine("</style></head><body>");

            // ── HEADER ──
            sb.AppendLine($@"
<div class='report-header'>
    <h1><span class='shield'>&#x1F6E1;</span>Security Header Report</h1>
    <div class='meta'>Gerado em {DateTime.Now:dd/MM/yyyy} &agrave;s {DateTime.Now:HH:mm:ss} &mdash; {items.Count} sistema(s) analisado(s)</div>
</div>");

            // ── RESUMO GLOBAL ──
            sb.AppendLine($@"
<div class='summary-bar'>
    <div class='summary-card total'><div class='number'>{totalChecks}</div><div class='label'>Verificações <span class='info-icon'>&#x2139;<span class='info-tip'>Total de verificações realizadas (headers, cookies e server exposure)</span></span></div></div>
    <div class='summary-card ok'><div class='number'>{totalOk}</div><div class='label'>Conforme <span class='info-icon'>&#x2139;<span class='info-tip'>Configurações que atendem ao baseline de segurança</span></span></div></div>
    <div class='summary-card warn'><div class='number'>{totalWarn}</div><div class='label'>Atenção <span class='info-icon'>&#x2139;<span class='info-tip'>Valor permitido, mas menos seguro que o recomendado</span></span></div></div>
    <div class='summary-card fail'><div class='number'>{totalFail}</div><div class='label'>Não conforme <span class='info-icon'>&#x2139;<span class='info-tip'>Configurações com valor incorreto, flags de cookie ausentes ou informações do servidor visíveis</span></span></div></div>
    <div class='summary-card missing'><div class='number'>{totalMissing}</div><div class='label'>Ausente <span class='info-icon'>&#x2139;<span class='info-tip'>Headers de segurança não configurados</span></span></div></div>
</div>");

            sb.AppendLine("<div class='content'>");

            // ── URLs ──
            foreach (var it in items)
            {
                var refHeaders = GetReferenceHeadersFor(it);

                string typeBadge = it.IsApi
                    ? "<span class='badge-type badge-type-api'>&#x2699;&#xFE0F; API</span>"
                    : "<span class='badge-type badge-type-website'>&#x1F310; Website</span>";

                sb.AppendLine("<div class='url-section'>");
                sb.AppendLine($@"
<div class='url-header'>
    <span class='url-icon'>🌐</span>
    <h2>{System.Net.WebUtility.HtmlEncode(it.Url)}</h2>
    {typeBadge}
</div>");

                sb.AppendLine("<div class='url-body'>");

                if (!string.IsNullOrEmpty(it.Error))
                {
                    sb.AppendLine($"<div class='error-box'>Erro: {System.Net.WebUtility.HtmlEncode(it.Error)}</div>");
                    sb.AppendLine("</div></div>");
                    continue;
                }

                // Tabela de headers
                sb.AppendLine("<table><thead><tr><th>Header</th><th>Status</th><th>Valor Atual</th><th>Esperado</th><th>Detalhes</th></tr></thead><tbody>");

                var existingHeaders = it.Comparisons.HeaderChecks
                    .ToDictionary(h => h.Name, StringComparer.OrdinalIgnoreCase);

                foreach (var kv in refHeaders)
                {
                    var headerName = kv.Key;
                    existingHeaders.TryGetValue(headerName, out var h);

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
                            refHeaders.TryGetValue(headerName, out expected);
                        }

                        sb.AppendLine($@"
<tr>
    <td><strong>{System.Net.WebUtility.HtmlEncode(headerName)}</strong></td>
    <td><span class='badge badge-missing'>&#x26D4; Ausente</span></td>
    <td class='mono'>&mdash;</td>
    <td class='mono'>{expected}</td>
    <td>Header não configurado</td>
</tr>");
                        continue;
                    }

                    string expectedValue;

                    if (!string.IsNullOrWhiteSpace(h.Expected))
                        expectedValue = h.Expected;
                    else
                        refHeaders.TryGetValue(h.Name, out expectedValue);

                    bool isWarning = !string.IsNullOrEmpty(h.Message) && h.Message.StartsWith(WARNING);

                    string status;
                    if (isWarning)
                        status = "<span class='badge badge-warn'>&#x26A0;&#xFE0F; Atenção</span>";
                    else if (h.Passed)
                        status = "<span class='badge badge-ok'>&#x2714;&#xFE0F; OK</span>";
                    else if (string.IsNullOrEmpty(h.Actual))
                        status = "<span class='badge badge-missing'>&#x26D4; Ausente</span>";
                    else
                        status = "<span class='badge badge-fail'>&#x274C; Falha</span>";

                    bool isRichHtml =
                        headerName.Equals("Content-Security-Policy", StringComparison.OrdinalIgnoreCase) ||
                        headerName.Equals("Permissions-Policy", StringComparison.OrdinalIgnoreCase);

                    string expectedRendered = isRichHtml
                        ? (expectedValue ?? "")
                        : System.Net.WebUtility.HtmlEncode(expectedValue ?? "");

                    string details = System.Net.WebUtility.HtmlEncode(h.Message ?? "")
                        .Replace("\n\n", "<br><br>")
                        .Replace(WARNING, "");

                    sb.AppendLine($@"
<tr>
    <td><strong>{System.Net.WebUtility.HtmlEncode(h.Name)}</strong></td>
    <td>{status}</td>
    <td class='mono'>{System.Net.WebUtility.HtmlEncode(h.Actual ?? "(vazio)")}</td>
    <td class='mono'>{expectedRendered}</td>
    <td class='details'>{details}</td>
</tr>");
                }

                sb.AppendLine("</tbody></table>");

                // ── Cookies ──
                sb.AppendLine("<div class='sub-title'>Cookies</div>");

                if (it.CookieChecks != null && it.CookieChecks.Any())
                {
                    sb.AppendLine("<table><thead><tr><th>Cookie</th><th>Status</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Detalhes</th></tr></thead><tbody>");

                    foreach (var c in it.CookieChecks)
                    {
                        string status = c.Ignored
                            ? "<span class='badge badge-ignored'>&#x23F8; Ignorado</span>"
                            : c.Passed
                                ? "<span class='badge badge-ok'>&#x2714;&#xFE0F; OK</span>"
                                : "<span class='badge badge-fail'>&#x274C; Falha</span>";

                        string secBadge = c.Secure
                            ? "<span class='badge badge-ok'>&#x2714;&#xFE0F;</span>"
                            : "<span class='badge badge-fail'>&#x274C;</span>";
                        string httpBadge = c.HttpOnly
                            ? "<span class='badge badge-ok'>&#x2714;&#xFE0F;</span>"
                            : "<span class='badge badge-fail'>&#x274C;</span>";

                        string sameSiteBadge = !string.IsNullOrEmpty(c.SameSite)
                            ? System.Net.WebUtility.HtmlEncode(c.SameSite)
                            : "<span class='badge badge-fail'>&#x274C;</span>";

                        sb.AppendLine($@"
<tr class='{(c.Ignored ? "row-ignored" : "")}'>
    <td><strong>{System.Net.WebUtility.HtmlEncode(c.Name)}</strong></td>
    <td>{status}</td>
    <td>{secBadge}</td>
    <td>{httpBadge}</td>
    <td>{sameSiteBadge}</td>
    <td>{System.Net.WebUtility.HtmlEncode(c.Message)}</td>
</tr>");
                    }

                    sb.AppendLine("</tbody></table>");
                }
                else
                {
                    sb.AppendLine("<p class='no-cookies'>Nenhum cookie identificado na resposta HTTP.</p>");
                }

                // ── Server exposure ──
                sb.AppendLine("<div class='sub-title'>Server Exposure</div>");
                if (it.Comparisons.ServerExposed)
                {
                    sb.AppendLine($"<div class='server-exposed'>Cabeçalhos expõem informações do servidor. <strong>Server:</strong> {System.Net.WebUtility.HtmlEncode(it.Comparisons.ServerHeader ?? "(vazio)")} &mdash; <strong>X-Powered-By:</strong> {System.Net.WebUtility.HtmlEncode(it.Comparisons.XPoweredBy ?? "(vazio)")}</div>");
                }
                else
                {
                    sb.AppendLine("<div class='server-ok'>Informações do servidor ocultas (conforme).</div>");
                }

                sb.AppendLine("</div>"); // url-body
                sb.AppendLine("</div>"); // url-section
            }

            // ── Legenda ──
            sb.AppendLine(@"
<div class='legend-section'>
    <h3>Legenda</h3>
    <div class='legend-grid'>
        <div class='legend-item'><span class='badge badge-ok'>&#x2714;&#xFE0F; OK</span> Configuração correta</div>
        <div class='legend-item'><span class='badge badge-warn'>&#x26A0;&#xFE0F; Atenção</span> Deve ser analisado</div>
        <div class='legend-item'><span class='badge badge-fail'>&#x274C; Falha</span> Deve ser corrigido</div>
        <div class='legend-item'><span class='badge badge-missing'>&#x26D4; Ausente</span> Deve ser implementado</div>
        <div class='legend-item'><span class='badge-type badge-type-website'>&#x1F310; Website</span> Verificação completa</div>
        <div class='legend-item'><span class='badge-type badge-type-api'>&#x2699;&#xFE0F; API</span> Headers relevantes para API</div>
    </div>
</div>");

            // ── Footer ──
            sb.AppendLine($@"
<div class='report-footer'>
    Security Header Scanner &mdash; CGSIC/MAPA &mdash; Relatório gerado em {DateTime.Now:dd/MM/yyyy HH:mm:ss}
</div>");

            sb.AppendLine("</div>"); // content
            sb.AppendLine("</body></html>");
            return sb.ToString();
        }
    }

    public class ReportItem
    {
        public string Url { get; set; } = "";
        public bool IsApi { get; set; }
        public DateTime TimestampUtc { get; set; }
        public string? Error { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public ComparisonsResult Comparisons { get; set; } = new ComparisonsResult();
        public List<ParsedCookie>? Cookies { get; set; }
        public List<CookieCheckResult>? CookieChecks { get; set; }
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

    public class CookieCheckResult
    {
        public string Name { get; set; } = "";
        public bool Secure { get; set; }
        public bool HttpOnly { get; set; }
        public string? SameSite { get; set; }
        public bool Ignored { get; set; }

        public bool Passed { get; set; }
        public string Message { get; set; } = "";
    }

    public static class Scanner
    {
        public static async Task<string> RunScan(
    List<(string Url, bool IsApi)> urls,
    Action<int>? progress = null)
        {
            Directory.CreateDirectory("Reports");

            var reportItems = new List<ReportItem>();

            int total = urls.Count;
            int done = 0;

            foreach (var item in urls)
            {
                reportItems.Add(
                    await SecurityAnalyzer.AnalyzeUrl(
                        item.Url,
                        item.IsApi));

                done++;

                int percent =
                    (int)((done / (double)total) * 100);

                progress?.Invoke(percent);
            }

            var timestamp =
                DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");

            var outPath =
                Path.Combine(
                    "Reports",
                    $"report_{timestamp}.html");

            File.WriteAllText(
                outPath,
                SecurityAnalyzer.RenderHtml(
                    reportItems,
                    timestamp));

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