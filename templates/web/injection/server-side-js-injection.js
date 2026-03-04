#!/usr/bin/env node
/**
 * Template: Server-side JS Injection
 * Purpose: Detects server-side JavaScript injection vulnerabilities
 * Severity: CRITICAL
 * CWE: CWE-94 (Improper Control of Generation of Code - Code Injection)
 * 
 * Description:
 * Detects Node.js applications vulnerable to server-side JavaScript injection
 * through dangerous functions like eval(), Function(), vm.runInNewContext(),
 * and template engines with unsafe evaluation.
 * 
 * Vulnerability Vectors:
 * 1. eval() with user input
 * 2. Function() constructor with user input
 * 3. vm.runInNewContext/runInThisContext with user input
 * 4. child_process.exec with unsanitized input
 * 5. Unsafe template rendering (EJS, Pug, Handlebars)
 * 
 * Detection Methods:
 * - Probing with math expressions (7*7, 6+6)
 * - Template injection payloads
 * - Code execution indicators
 * - Error-based detection
 * - Time-based detection
 * 
 * Author: CERT-X-GEN Team
 * Date: 2026-02-02
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

class ServerSideJSInjection {
    constructor(target, port) {
        this.target = target;
        this.port = port;
        this.timeout = 10000;
        
        // Detection payloads
        this.payloads = [
            // Math expressions (should evaluate to specific values)
            { payload: '${7*7}', expected: '49', type: 'template_literal' },
            { payload: '{{7*7}}', expected: '49', type: 'handlebars' },
            { payload: '<%= 7*7 %>', expected: '49', type: 'ejs' },
            { payload: '#{7*7}', expected: '49', type: 'pug' },
            
            // Function-based
            { payload: 'Function("return 7*7")()', expected: '49', type: 'function_constructor' },
            
            // Global object access
            { payload: '${global.process.version}', expected: 'v', type: 'global_access' },
            { payload: '{{this.constructor.constructor("return this.process.version")()}}', expected: 'v', type: 'constructor_escape' },
            
            // Command execution indicators
            { payload: '${require("child_process").execSync("echo INJECTED").toString()}', expected: 'INJECTED', type: 'require_exec' },
            
            // Error-based
            { payload: '${undefined.test}', expected: 'error', type: 'error_trigger' },
            { payload: '{{undefined.test}}', expected: 'error', type: 'error_trigger' }
        ];
        
        // Common injection points
        this.injectionPoints = [
            { param: 'q', method: 'GET' },
            { param: 'search', method: 'GET' },
            { param: 'name', method: 'GET' },
            { param: 'template', method: 'GET' },
            { param: 'expr', method: 'GET' },
            { param: 'code', method: 'GET' }
        ];
    }
    
    async scan() {
        const result = {
            template: 'server-side-js-injection',
            target: this.target,
            port: this.port,
            timestamp: new Date().toISOString(),
            findings: [],
            metadata: {
                http_accessible: false,
                injection_points_tested: 0,
                vulnerabilities_found: 0
            }
        };
        
        try {
            // Test HTTP connectivity
            const accessible = await this.checkHttpAccessible();
            
            if (!accessible) {
                result.findings.push({
                    severity: 'info',
                    confidence: 100,
                    title: 'HTTP Service Not Accessible',
                    description: `HTTP service not accessible on ${this.target}:${this.port}`,
                    remediation: 'Verify target is running an HTTP server'
                });
                return result;
            }
            
            result.metadata.http_accessible = true;
            
            // Test for injection vulnerabilities
            const vulnerabilities = await this.testInjections();
            result.metadata.injection_points_tested = this.injectionPoints.length * this.payloads.length;
            result.metadata.vulnerabilities_found = vulnerabilities.length;
            
            if (vulnerabilities.length > 0) {
                vulnerabilities.forEach(vuln => {
                    result.findings.push({
                        severity: vuln.severity,
                        confidence: vuln.confidence,
                        title: vuln.title,
                        description: vuln.description,
                        cwe: 'CWE-94',
                        remediation: vuln.remediation,
                        references: [
                            'https://owasp.org/www-community/attacks/Code_Injection',
                            'https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html'
                        ]
                    });
                });
            } else {
                result.findings.push({
                    severity: 'info',
                    confidence: 80,
                    title: 'No Server-side JS Injection Detected',
                    description: `Tested ${result.metadata.injection_points_tested} injection points - no vulnerabilities found`,
                    remediation: 'Continue following secure coding practices'
                });
            }
            
        } catch (error) {
            result.findings.push({
                severity: 'info',
                confidence: 50,
                title: 'Scan Error',
                description: `Error during scan: ${error.message}`,
                remediation: 'Check target accessibility and permissions'
            });
        }
        
        return result;
    }
    
    checkHttpAccessible() {
        return new Promise((resolve) => {
            const protocol = this.port === 443 ? https : http;
            const options = {
                hostname: this.target,
                port: this.port,
                path: '/',
                method: 'GET',
                timeout: this.timeout,
                rejectUnauthorized: false
            };
            
            const req = protocol.request(options, (res) => {
                resolve(true);
                res.resume();
            });
            
            req.on('error', () => {
                resolve(false);
            });
            
            req.on('timeout', () => {
                req.destroy();
                resolve(false);
            });
            
            req.end();
        });
    }
    
    async testInjections() {
        const vulnerabilities = [];
        const foundVulnerabilities = new Set();
        
        for (const point of this.injectionPoints) {
            for (const payloadData of this.payloads) {
                try {
                    const response = await this.sendPayload(point.param, payloadData.payload);
                    
                    if (response && response.body) {
                        const bodyLower = response.body.toLowerCase();
                        
                        // Check for expected output
                        if (payloadData.expected !== 'error') {
                            if (response.body.includes(payloadData.expected)) {
                                const vulnKey = `${point.param}-${payloadData.type}`;
                                
                                if (!foundVulnerabilities.has(vulnKey)) {
                                    foundVulnerabilities.add(vulnKey);
                                    
                                    vulnerabilities.push({
                                        severity: 'critical',
                                        confidence: 95,
                                        title: 'Server-side JavaScript Injection Detected',
                                        description: `Parameter '${point.param}' is vulnerable to server-side JavaScript injection. ` +
                                                   `Payload type: ${payloadData.type}. ` +
                                                   `The server evaluated the expression and returned the expected result '${payloadData.expected}'.`,
                                        remediation: 
                                            '1. Never use eval(), Function(), or vm.runInNewContext() with user input\n' +
                                            '2. Sanitize all user inputs before processing\n' +
                                            '3. Use safe template engines or disable code evaluation\n' +
                                            '4. Implement proper input validation and whitelisting\n' +
                                            '5. Use static analysis tools to detect dangerous patterns'
                                    });
                                }
                            }
                        } else {
                            // Error-based detection
                            if (bodyLower.includes('error') || 
                                bodyLower.includes('exception') ||
                                bodyLower.includes('undefined') ||
                                bodyLower.includes('cannot read') ||
                                bodyLower.includes('syntaxerror') ||
                                bodyLower.includes('referenceerror')) {
                                
                                const vulnKey = `${point.param}-error-based`;
                                
                                if (!foundVulnerabilities.has(vulnKey)) {
                                    foundVulnerabilities.add(vulnKey);
                                    
                                    vulnerabilities.push({
                                        severity: 'high',
                                        confidence: 75,
                                        title: 'Potential Server-side JS Injection (Error-based)',
                                        description: `Parameter '${point.param}' may be vulnerable to server-side JavaScript injection. ` +
                                                   `Error messages suggest code evaluation is occurring.`,
                                        remediation: 
                                            '1. Review code for eval() or similar dangerous functions\n' +
                                            '2. Implement proper error handling without exposing details\n' +
                                            '3. Sanitize all user inputs\n' +
                                            '4. Use safe alternatives to dynamic code execution'
                                    });
                                }
                            }
                        }
                    }
                } catch (error) {
                    // Continue testing other payloads
                    continue;
                }
            }
        }
        
        return vulnerabilities;
    }
    
    sendPayload(param, payload) {
        return new Promise((resolve) => {
            const protocol = this.port === 443 ? https : http;
            const encodedPayload = encodeURIComponent(payload);
            const path = `/?${param}=${encodedPayload}`;
            
            const options = {
                hostname: this.target,
                port: this.port,
                path: path,
                method: 'GET',
                timeout: this.timeout,
                rejectUnauthorized: false
            };
            
            const req = protocol.request(options, (res) => {
                let body = '';
                
                res.on('data', (chunk) => {
                    body += chunk;
                });
                
                res.on('end', () => {
                    resolve({
                        statusCode: res.statusCode,
                        body: body
                    });
                });
            });
            
            req.on('error', () => {
                resolve(null);
            });
            
            req.on('timeout', () => {
                req.destroy();
                resolve(null);
            });
            
            req.end();
        });
    }
}

// Main entry point
async function main() {
    if (process.argv.length !== 4) {
        console.error('Usage: server-side-js-injection.js <target> <port>');
        process.exit(1);
    }
    
    const target = process.argv[2];
    const port = parseInt(process.argv[3]);
    
    if (isNaN(port)) {
        console.error('Error: Port must be an integer');
        process.exit(1);
    }
    
    const scanner = new ServerSideJSInjection(target, port);
    const result = await scanner.scan();
    
    console.log(JSON.stringify(result, null, 2));
}

main().catch(error => {
    console.error(JSON.stringify({
        template: 'server-side-js-injection',
        error: error.message,
        findings: [{
            severity: 'info',
            title: 'Scan Failed',
            description: error.message
        }]
    }, null, 2));
    process.exit(1);
});
