#!/usr/bin/env node
/**
 * Template: Prototype Pollution
 * Purpose: Detects prototype pollution vulnerabilities in JavaScript applications
 * Severity: HIGH
 * CWE: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
 * 
 * Description:
 * Detects prototype pollution vulnerabilities where attackers can inject properties
 * into JavaScript object prototypes, potentially leading to:
 * - Privilege escalation
 * - Remote code execution
 * - Denial of service
 * - Authentication bypass
 * 
 * Vulnerability Vectors:
 * 1. JSON parsing with __proto__ manipulation
 * 2. Deep merge operations
 * 3. Object assignment with untrusted input
 * 4. Query parameter parsing
 * 5. Constructor prototype manipulation
 * 
 * Detection Methods:
 * - Tests common pollution vectors (__proto__, constructor.prototype)
 * - Checks for polluted properties in responses
 * - Verifies object prototype chain manipulation
 * - Tests JSON endpoints for pollution acceptance
 * 
 * Author: CERT-X-GEN Team
 * Date: 2026-02-02
 */

const http = require('http');
const https = require('https');

class PrototypePollution {
    constructor(target, port) {
        this.target = target;
        this.port = port;
        this.timeout = 10000;
        
        // Pollution test payloads
        this.payloads = [
            // __proto__ pollution
            { 
                payload: { '__proto__': { 'polluted': 'yes' } },
                indicator: 'polluted',
                type: '__proto__'
            },
            {
                payload: { '__proto__': { 'isAdmin': true } },
                indicator: 'isAdmin',
                type: '__proto__ privilege'
            },
            
            // Constructor pollution
            {
                payload: { 'constructor': { 'prototype': { 'polluted': 'yes' } } },
                indicator: 'polluted',
                type: 'constructor.prototype'
            },
            
            // Nested pollution
            {
                payload: { 'a': { '__proto__': { 'polluted': 'yes' } } },
                indicator: 'polluted',
                type: 'nested __proto__'
            },
            
            // Array pollution
            {
                payload: { 'arr[__proto__]': { 'polluted': 'yes' } },
                indicator: 'polluted',
                type: 'array notation'
            }
        ];
        
        // Common test endpoints
        this.endpoints = [
            '/api/user',
            '/api/profile',
            '/api/settings',
            '/user',
            '/profile',
            '/settings',
            '/api/v1/user',
            '/'
        ];
    }
    
    async scan() {
        const result = {
            template: 'prototype-pollution',
            target: this.target,
            port: this.port,
            timestamp: new Date().toISOString(),
            findings: [],
            metadata: {
                http_accessible: false,
                endpoints_tested: 0,
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
            
            // Test for prototype pollution
            const vulnerabilities = await this.testPrototypePollution();
            result.metadata.endpoints_tested = this.endpoints.length;
            result.metadata.vulnerabilities_found = vulnerabilities.length;
            
            if (vulnerabilities.length > 0) {
                vulnerabilities.forEach(vuln => {
                    result.findings.push({
                        severity: vuln.severity,
                        confidence: vuln.confidence,
                        title: vuln.title,
                        description: vuln.description,
                        cwe: 'CWE-1321',
                        remediation: vuln.remediation,
                        references: [
                            'https://portswigger.net/web-security/prototype-pollution',
                            'https://github.com/HoLyVieR/prototype-pollution-nsec18',
                            'https://cwe.mitre.org/data/definitions/1321.html'
                        ]
                    });
                });
            } else {
                result.findings.push({
                    severity: 'info',
                    confidence: 80,
                    title: 'No Prototype Pollution Detected',
                    description: `Tested ${result.metadata.endpoints_tested} endpoints - no vulnerabilities found`,
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
    
    async testPrototypePollution() {
        const vulnerabilities = [];
        const foundVulnerabilities = new Set();
        
        for (const endpoint of this.endpoints) {
            for (const payloadData of this.payloads) {
                try {
                    // Test with POST request containing pollution payload
                    const response = await this.sendPollutionPayload(endpoint, payloadData.payload);
                    
                    if (response && response.body) {
                        const bodyLower = response.body.toLowerCase();
                        const indicator = payloadData.indicator.toLowerCase();
                        
                        // Check if pollution indicator appears in response
                        if (bodyLower.includes(indicator) || 
                            bodyLower.includes(`"${indicator}"`) ||
                            bodyLower.includes(`'${indicator}'`)) {
                            
                            const vulnKey = `${endpoint}-${payloadData.type}`;
                            
                            if (!foundVulnerabilities.has(vulnKey)) {
                                foundVulnerabilities.add(vulnKey);
                                
                                vulnerabilities.push({
                                    severity: 'high',
                                    confidence: 85,
                                    title: 'Prototype Pollution Vulnerability Detected',
                                    description: 
                                        `Endpoint '${endpoint}' is vulnerable to prototype pollution via ${payloadData.type}. ` +
                                        `The application accepts and processes __proto__ or constructor.prototype manipulation, ` +
                                        `allowing attackers to inject properties into JavaScript object prototypes.`,
                                    remediation:
                                        '1. Sanitize user input before object operations\n' +
                                        '2. Use Object.create(null) for objects without prototypes\n' +
                                        '3. Freeze Object.prototype to prevent modifications\n' +
                                        '4. Use JSON schema validation to block __proto__ keys\n' +
                                        '5. Implement allowlist for object properties\n' +
                                        '6. Update vulnerable dependencies (lodash, jQuery, etc.)\n' +
                                        '7. Use secure merge functions that prevent pollution'
                                });
                            }
                        }
                    }
                    
                    // Also test via query parameters
                    const queryResponse = await this.testQueryPollution(endpoint, payloadData);
                    
                    if (queryResponse && queryResponse.vulnerable) {
                        const vulnKey = `${endpoint}-query-${payloadData.type}`;
                        
                        if (!foundVulnerabilities.has(vulnKey)) {
                            foundVulnerabilities.add(vulnKey);
                            
                            vulnerabilities.push({
                                severity: 'high',
                                confidence: 80,
                                title: 'Query Parameter Prototype Pollution',
                                description:
                                    `Endpoint '${endpoint}' accepts prototype pollution via query parameters. ` +
                                    `URL parameters like ?__proto__[key]=value can modify object prototypes.`,
                                remediation:
                                    '1. Sanitize query parameters before use\n' +
                                    '2. Reject requests with __proto__ or constructor keys\n' +
                                    '3. Use safe query parsing libraries\n' +
                                    '4. Validate parameter names against allowlist'
                            });
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
    
    sendPollutionPayload(endpoint, payload) {
        return new Promise((resolve) => {
            const protocol = this.port === 443 ? https : http;
            const jsonPayload = JSON.stringify(payload);
            
            const options = {
                hostname: this.target,
                port: this.port,
                path: endpoint,
                method: 'POST',
                timeout: this.timeout,
                rejectUnauthorized: false,
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(jsonPayload)
                }
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
            
            req.write(jsonPayload);
            req.end();
        });
    }
    
    async testQueryPollution(endpoint, payloadData) {
        return new Promise((resolve) => {
            const protocol = this.port === 443 ? https : http;
            
            // Build query string with pollution attempt
            const pollutionQuery = '__proto__[polluted]=yes';
            const path = `${endpoint}?${pollutionQuery}`;
            
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
                    // Check if pollution indicator appears
                    const vulnerable = body.toLowerCase().includes('polluted');
                    resolve({ vulnerable, body });
                });
            });
            
            req.on('error', () => {
                resolve({ vulnerable: false });
            });
            
            req.on('timeout', () => {
                req.destroy();
                resolve({ vulnerable: false });
            });
            
            req.end();
        });
    }
}

// Main entry point
async function main() {
    if (process.argv.length !== 4) {
        console.error('Usage: prototype-pollution.js <target> <port>');
        process.exit(1);
    }
    
    const target = process.argv[2];
    const port = parseInt(process.argv[3]);
    
    if (isNaN(port)) {
        console.error('Error: Port must be an integer');
        process.exit(1);
    }
    
    const scanner = new PrototypePollution(target, port);
    const result = await scanner.scan();
    
    console.log(JSON.stringify(result, null, 2));
}

main().catch(error => {
    console.error(JSON.stringify({
        template: 'prototype-pollution',
        error: error.message,
        findings: [{
            severity: 'info',
            title: 'Scan Failed',
            description: error.message
        }]
    }, null, 2));
    process.exit(1);
});
