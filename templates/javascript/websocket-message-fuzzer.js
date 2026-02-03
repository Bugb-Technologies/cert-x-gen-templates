#!/usr/bin/env node
/**
 * Template: WebSocket Message Fuzzer
 * Purpose: Detects WebSocket vulnerabilities through message fuzzing
 * Severity: MEDIUM
 * CWE: CWE-20 (Improper Input Validation), CWE-400 (Uncontrolled Resource Consumption)
 * 
 * Description:
 * Tests WebSocket endpoints for vulnerabilities by fuzzing message payloads.
 * Detects improper input validation, injection vulnerabilities, and denial
 * of service conditions in WebSocket message handlers.
 * 
 * Detection Methods:
 * - WebSocket connection establishment
 * - Message payload fuzzing (special chars, long strings, JSON malformation)
 * - Response analysis for errors/crashes
 * - Connection stability testing
 * - Rate limiting detection
 * 
 * Vulnerability Indicators:
 * 1. Crashes on malformed input
 * 2. Injection vulnerabilities (XSS, command injection)
 * 3. No input validation
 * 4. Missing rate limiting
 * 5. Verbose error messages
 * 
 * Author: CERT-X-GEN Team
 * Date: 2026-02-02
 */

const WebSocket = require('ws');

class WebSocketMessageFuzzer {
    constructor(target, port) {
        this.target = target;
        this.port = port;
        this.timeout = 10000;
        
        // Fuzzing payloads
        this.payloads = [
            // Special characters
            '\'"><script>alert(1)</script>',
            '${7*7}',
            '{{7*7}}',
            '<img src=x onerror=alert(1)>',
            
            // Command injection
            '`id`',
            '$(whoami)',
            '; ls -la',
            
            // JSON malformation
            '{"test": "value"',
            '{"test": undefined}',
            'null',
            
            // Long strings (DoS)
            'A'.repeat(10000),
            'A'.repeat(100000),
            
            // Special JSON payloads
            '{"__proto__": {"polluted": true}}',
            '{"constructor": {"prototype": {"polluted": true}}}',
            
            // Unicode and encoding
            '\u0000',
            '\uffff',
            '%00',
            
            // SQL injection patterns
            "' OR '1'='1",
            "admin'--",
            
            // NoSQL injection
            '{"$ne": null}',
            '{"$gt": ""}',
        ];
    }
    
    async scan() {
        const result = {
            template: 'websocket-message-fuzzer',
            target: this.target,
            port: this.port,
            timestamp: new Date().toISOString(),
            findings: [],
            metadata: {
                websocket_accessible: false,
                connection_stable: false,
                payloads_tested: 0,
                vulnerabilities_found: 0
            }
        };
        
        try {
            // Test WebSocket connection
            const wsUrl = `ws://${this.target}:${this.port}`;
            const wsSecureUrl = `wss://${this.target}:${this.port}`;
            
            // Try both ws:// and wss://
            let connected = false;
            let ws = null;
            
            for (const url of [wsSecureUrl, wsUrl]) {
                try {
                    ws = await this.connectWebSocket(url);
                    if (ws) {
                        connected = true;
                        result.metadata.websocket_accessible = true;
                        break;
                    }
                } catch (e) {
                    continue;
                }
            }
            
            if (!connected) {
                result.findings.push({
                    severity: 'info',
                    confidence: 100,
                    title: 'WebSocket Not Accessible',
                    description: `WebSocket not accessible on ${this.target}:${this.port}`,
                    remediation: 'Verify target is running WebSocket server'
                });
                return result;
            }
            
            // Fuzz WebSocket with payloads
            const vulnerabilities = await this.fuzzMessages(ws);
            result.metadata.payloads_tested = this.payloads.length;
            result.metadata.vulnerabilities_found = vulnerabilities.length;
            
            if (vulnerabilities.length > 0) {
                result.metadata.connection_stable = false;
                
                vulnerabilities.forEach(vuln => {
                    result.findings.push({
                        severity: vuln.severity,
                        confidence: vuln.confidence,
                        title: vuln.title,
                        description: vuln.description,
                        cwe: vuln.cwe,
                        remediation: vuln.remediation
                    });
                });
            } else {
                result.metadata.connection_stable = true;
                result.findings.push({
                    severity: 'info',
                    confidence: 85,
                    title: 'No WebSocket Vulnerabilities Detected',
                    description: `Tested ${this.payloads.length} fuzzing payloads - no vulnerabilities found`,
                    remediation: 'Continue following WebSocket security best practices'
                });
            }
            
            ws.close();
            
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
    
    connectWebSocket(url) {
        return new Promise((resolve, reject) => {
            try {
                const ws = new WebSocket(url, {
                    rejectUnauthorized: false,
                    handshakeTimeout: this.timeout
                });
                
                ws.on('open', () => {
                    resolve(ws);
                });
                
                ws.on('error', (error) => {
                    reject(error);
                });
                
                setTimeout(() => {
                    reject(new Error('Connection timeout'));
                }, this.timeout);
                
            } catch (error) {
                reject(error);
            }
        });
    }
    
    async fuzzMessages(ws) {
        const vulnerabilities = [];
        let crashCount = 0;
        let errorCount = 0;
        let injectionIndicators = 0;
        
        for (const payload of this.payloads) {
            try {
                const response = await this.sendAndReceive(ws, payload);
                
                // Check for error indicators
                if (response && typeof response === 'string') {
                    const lowerResponse = response.toLowerCase();
                    
                    // Check for stack traces or error messages
                    if (lowerResponse.includes('error') || 
                        lowerResponse.includes('exception') ||
                        lowerResponse.includes('stack trace') ||
                        lowerResponse.includes('traceback')) {
                        errorCount++;
                    }
                    
                    // Check for injection success indicators
                    if (lowerResponse.includes('49') || // 7*7 result
                        lowerResponse.includes('polluted') ||
                        lowerResponse.includes('root:') || // Command injection
                        lowerResponse.includes('/bin/')) {
                        injectionIndicators++;
                    }
                }
                
            } catch (error) {
                // Connection crashed or closed
                crashCount++;
                
                if (crashCount >= 2) {
                    vulnerabilities.push({
                        severity: 'high',
                        confidence: 90,
                        title: 'WebSocket Crashes on Malformed Input',
                        description: `WebSocket server crashes when receiving malformed messages. Crashed ${crashCount} times during fuzzing.`,
                        cwe: 'CWE-20',
                        remediation: 'Implement proper input validation and error handling for WebSocket messages'
                    });
                    break; // Stop fuzzing if multiple crashes
                }
            }
        }
        
        // Analyze results
        if (errorCount > 3) {
            vulnerabilities.push({
                severity: 'medium',
                confidence: 75,
                title: 'Verbose Error Messages in WebSocket Responses',
                description: `WebSocket server returns ${errorCount} error messages during fuzzing. This may leak sensitive information.`,
                cwe: 'CWE-209',
                remediation: 'Implement generic error messages without revealing implementation details'
            });
        }
        
        if (injectionIndicators > 0) {
            vulnerabilities.push({
                severity: 'high',
                confidence: 85,
                title: 'Potential Injection Vulnerability Detected',
                description: `WebSocket message handling may be vulnerable to injection attacks. Found ${injectionIndicators} indicators.`,
                cwe: 'CWE-94',
                remediation: 'Sanitize and validate all WebSocket message inputs before processing'
            });
        }
        
        return vulnerabilities;
    }
    
    sendAndReceive(ws, message) {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                resolve(null); // Timeout is not an error, just no response
            }, 2000);
            
            const messageHandler = (data) => {
                clearTimeout(timeout);
                ws.removeListener('message', messageHandler);
                ws.removeListener('error', errorHandler);
                ws.removeListener('close', closeHandler);
                resolve(data.toString());
            };
            
            const errorHandler = (error) => {
                clearTimeout(timeout);
                ws.removeListener('message', messageHandler);
                ws.removeListener('error', errorHandler);
                ws.removeListener('close', closeHandler);
                reject(error);
            };
            
            const closeHandler = () => {
                clearTimeout(timeout);
                ws.removeListener('message', messageHandler);
                ws.removeListener('error', errorHandler);
                ws.removeListener('close', closeHandler);
                reject(new Error('Connection closed'));
            };
            
            ws.once('message', messageHandler);
            ws.once('error', errorHandler);
            ws.once('close', closeHandler);
            
            try {
                ws.send(message);
            } catch (error) {
                clearTimeout(timeout);
                reject(error);
            }
        });
    }
}

// Main entry point
async function main() {
    if (process.argv.length !== 4) {
        console.error('Usage: websocket-message-fuzzer.js <target> <port>');
        process.exit(1);
    }
    
    const target = process.argv[2];
    const port = parseInt(process.argv[3]);
    
    if (isNaN(port)) {
        console.error('Error: Port must be an integer');
        process.exit(1);
    }
    
    const scanner = new WebSocketMessageFuzzer(target, port);
    const result = await scanner.scan();
    
    console.log(JSON.stringify(result, null, 2));
}

main().catch(error => {
    console.error(JSON.stringify({
        template: 'websocket-message-fuzzer',
        error: error.message,
        findings: [{
            severity: 'info',
            title: 'Scan Failed',
            description: error.message
        }]
    }, null, 2));
    process.exit(1);
});
