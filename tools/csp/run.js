const { CspEvaluator } = require('csp_evaluator/dist/evaluator');
const { CspParser } = require('csp_evaluator/dist/parser');

function analyze(csp) {
    const parsed = new CspParser(csp).csp;
    const evaluator = new CspEvaluator(parsed);
    const findings = evaluator.evaluate();

    return findings.map(f => ({
        type: f.type || null,
        description: f.description || null,
        severity: f.severity || null,
        directive: f.directive || null,
        value: f.value || null
    }));
}

const input = process.argv[2];

if (!input) {
    console.log(JSON.stringify({ error: "Missing CSP" }));
    process.exit(1);
}

try {
    const result = analyze(input);
    console.log(JSON.stringify(result));
} catch (e) {
    console.log(JSON.stringify({ error: e.toString() }));
    process.exit(2);
}
