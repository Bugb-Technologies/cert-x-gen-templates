// CERT-X-GEN PostgreSQL Default Credentials Detection
//
// @id: postgresql-default-credentials
// @name: PostgreSQL Default Credentials Detection
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects PostgreSQL servers with default or weak credentials
// @tags: postgresql, database, default-credentials, authentication
// @cwe: CWE-798
// @cvss: 9.8
// @references: https://www.postgresql.org/docs/current/auth-methods.html
// @confidence: 98
// @version: 1.0.0
//
// WHY GO?
// PostgreSQL auth detection benefits from:
// - Native network handling with proper timeout control
// - Binary protocol parsing (PostgreSQL wire protocol)
// - Compiled performance for credential testing
// - Cross-platform binary distribution
//

package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// Template metadata
var templateID = "postgresql-default-credentials"
var templateName = "PostgreSQL Default Credentials Detection"
var severity = "critical"
var confidence = 98

// Default credentials to test
var defaultCredentials = []struct {
	Username string
	Password string
}{
	{"postgres", ""},
	{"postgres", "postgres"},
	{"postgres", "password"},
	{"postgres", "admin"},
	{"postgres", "root"},
	{"admin", "admin"},
	{"admin", "password"},
	{"root", "root"},
}


// Finding structure
type Finding struct {
	TemplateID   string                 `json:"template_id"`
	TemplateName string                 `json:"template_name"`
	Severity     string                 `json:"severity"`
	Confidence   int                    `json:"confidence"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Evidence     map[string]interface{} `json:"evidence"`
	MatchedAt    string                 `json:"matched_at"`
	Host         string                 `json:"host"`
	Port         int                    `json:"port"`
	CWE          string                 `json:"cwe"`
	CVSSScore    float64                `json:"cvss_score"`
	Remediation  string                 `json:"remediation"`
}

// PostgreSQL Scanner
type PgScanner struct {
	Host     string
	Port     int
	Timeout  time.Duration
	conn     net.Conn
	Version  string
	Database string
}

// Create new scanner
func NewPgScanner(host string, port int) *PgScanner {
	return &PgScanner{
		Host:    host,
		Port:    port,
		Timeout: 10 * time.Second,
	}
}

// Connect to PostgreSQL
func (s *PgScanner) Connect() error {
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	conn, err := net.DialTimeout("tcp", addr, s.Timeout)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// Close connection
func (s *PgScanner) Close() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

// Build startup message
func (s *PgScanner) buildStartupMessage(user, database string) []byte {
	// Protocol version 3.0
	params := map[string]string{
		"user":             user,
		"database":         database,
		"client_encoding":  "UTF8",
		"application_name": "cert-x-gen",
	}

	// Calculate message size
	msgSize := 4 + 4 // length + protocol version
	for k, v := range params {
		msgSize += len(k) + 1 + len(v) + 1
	}
	msgSize += 1 // null terminator

	msg := make([]byte, msgSize)
	offset := 0

	// Message length (including self)
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgSize))
	offset += 4

	// Protocol version 3.0
	binary.BigEndian.PutUint32(msg[offset:], 196608) // 3 << 16
	offset += 4

	// Parameters
	for k, v := range params {
		copy(msg[offset:], k)
		offset += len(k) + 1
		copy(msg[offset:], v)
		offset += len(v) + 1
	}

	return msg
}


// Build password message (MD5 auth)
func (s *PgScanner) buildPasswordMessage(user, password string, salt []byte) []byte {
	// MD5 password: md5 + md5(md5(password + user) + salt)
	inner := md5.Sum([]byte(password + user))
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum(append([]byte(innerHex), salt...))
	pwHash := "md5" + hex.EncodeToString(outer[:])

	msgLen := 4 + 1 + len(pwHash) + 1
	msg := make([]byte, msgLen)
	msg[0] = 'p' // Password message
	binary.BigEndian.PutUint32(msg[1:], uint32(msgLen-1))
	copy(msg[5:], pwHash)

	return msg
}

// Build cleartext password message
func (s *PgScanner) buildCleartextPassword(password string) []byte {
	msgLen := 4 + 1 + len(password) + 1
	msg := make([]byte, msgLen)
	msg[0] = 'p'
	binary.BigEndian.PutUint32(msg[1:], uint32(msgLen-1))
	copy(msg[5:], password)
	return msg
}

// Try authentication with credentials
func (s *PgScanner) TryAuth(user, password, database string) (bool, string, error) {
	if err := s.Connect(); err != nil {
		return false, "", err
	}
	defer s.Close()

	s.conn.SetDeadline(time.Now().Add(s.Timeout))

	// Send startup message
	startup := s.buildStartupMessage(user, database)
	if _, err := s.conn.Write(startup); err != nil {
		return false, "", err
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := s.conn.Read(buf)
	if err != nil {
		return false, "", err
	}

	if n < 1 {
		return false, "", fmt.Errorf("empty response")
	}

	msgType := buf[0]

	switch msgType {
	case 'R': // Authentication request
		if n < 9 {
			return false, "", fmt.Errorf("invalid auth response")
		}
		authType := binary.BigEndian.Uint32(buf[5:9])

		switch authType {
		case 0: // AuthenticationOk - no password needed!
			return true, "trust (no password)", nil

		case 3: // CleartextPassword
			pwMsg := s.buildCleartextPassword(password)
			if _, err := s.conn.Write(pwMsg); err != nil {
				return false, "", err
			}
			
			n, err = s.conn.Read(buf)
			if err != nil {
				return false, "", err
			}
			if n > 0 && buf[0] == 'R' && n >= 9 {
				if binary.BigEndian.Uint32(buf[5:9]) == 0 {
					return true, "cleartext password", nil
				}
			}

		case 5: // MD5Password
			if n < 13 {
				return false, "", fmt.Errorf("invalid MD5 auth response")
			}
			salt := buf[9:13]
			pwMsg := s.buildPasswordMessage(user, password, salt)
			if _, err := s.conn.Write(pwMsg); err != nil {
				return false, "", err
			}

			n, err = s.conn.Read(buf)
			if err != nil {
				return false, "", err
			}
			if n > 0 && buf[0] == 'R' && n >= 9 {
				if binary.BigEndian.Uint32(buf[5:9]) == 0 {
					return true, "md5 password", nil
				}
			}
		}

	case 'E': // Error
		return false, "", nil
	}

	return false, "", nil
}


// Scan for default credentials
func (s *PgScanner) Scan() []Finding {
	var findings []Finding
	databases := []string{"postgres", "template1"}

	for _, db := range databases {
		for _, cred := range defaultCredentials {
			success, authMethod, err := s.TryAuth(cred.Username, cred.Password, db)
			if err != nil {
				continue
			}

			if success {
				pwDisplay := cred.Password
				if pwDisplay == "" {
					pwDisplay = "(empty)"
				}

				desc := fmt.Sprintf(
					"PostgreSQL server at %s:%d allows login with %s credentials (user: '%s', password: '%s'). "+
						"Auth method: %s. Database: %s. "+
						"Default credentials allow full database access including data exfiltration, modification, and privilege escalation.",
					s.Host, s.Port, "default", cred.Username, pwDisplay, authMethod, db,
				)

				finding := Finding{
					TemplateID:   templateID,
					TemplateName: templateName,
					Severity:     severity,
					Confidence:   confidence,
					Title:        fmt.Sprintf("PostgreSQL Default Credentials on %s:%d", s.Host, s.Port),
					Description:  desc,
					Evidence: map[string]interface{}{
						"username":    cred.Username,
						"password":    pwDisplay,
						"database":    db,
						"auth_method": authMethod,
						"protocol":    "postgresql",
					},
					MatchedAt:   fmt.Sprintf("%s:%d", s.Host, s.Port),
					Host:        s.Host,
					Port:        s.Port,
					CWE:         "CWE-798",
					CVSSScore:   9.8,
					Remediation: "Change default PostgreSQL passwords. Disable trust authentication. Use strong password policies. Restrict network access to PostgreSQL port.",
				}
				findings = append(findings, finding)
				return findings // Found one, return immediately
			}
		}
	}

	return findings
}

func main() {
	// Get target from environment or args
	host := os.Getenv("CERT_X_GEN_TARGET_HOST")
	portStr := os.Getenv("CERT_X_GEN_TARGET_PORT")
	if portStr == "" {
		portStr = "5432"
	}

	if host == "" && len(os.Args) > 1 {
		host = os.Args[1]
	}
	if len(os.Args) > 2 {
		portStr = os.Args[2]
	}

	if host == "" {
		fmt.Fprintln(os.Stderr, "Usage: postgresql-default-credentials <host> [port]")
		fmt.Fprintln(os.Stderr, "Or set CERT_X_GEN_TARGET_HOST environment variable")
		fmt.Println("[]")
		os.Exit(0)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 5432
	}

	scanner := NewPgScanner(host, port)
	findings := scanner.Scan()

	// Output JSON (ensure empty array, not null)
	if findings == nil {
		findings = []Finding{}
	}
	output, _ := json.MarshalIndent(findings, "", "  ")
	fmt.Println(string(output))
}
