// @id: docker-api-unauth
// @name: Docker API Unauthenticated Access
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects Docker daemon APIs exposed without authentication allowing full container control
// @tags: docker, container, api, rce, cloud-native
// @cwe: CWE-306
// @cvss: 9.8
// @references: https://docs.docker.com/engine/api/, https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker
// @confidence: 98
// @version: 1.0.0
//
// WHY GO?
// Docker is written in Go. The entire container ecosystem (Kubernetes, containerd, etc.) is Go.
// Go provides:
// - Native JSON marshaling/unmarshaling
// - Excellent HTTP client libraries
// - Goroutines for concurrent API calls
// - Same ecosystem as the target technology

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// DockerInfo represents the /info endpoint response
type DockerInfo struct {
	ServerVersion     string `json:"ServerVersion"`
	APIVersion        string `json:"ApiVersion"`
	OperatingSystem   string `json:"OperatingSystem"`
	Architecture      string `json:"Architecture"`
	Containers        int    `json:"Containers"`
	ContainersRunning int    `json:"ContainersRunning"`
	ContainersPaused  int    `json:"ContainersPaused"`
	ContainersStopped int    `json:"ContainersStopped"`
	Images            int    `json:"Images"`
	Driver            string `json:"Driver"`
	MemTotal          int64  `json:"MemTotal"`
	NCPU              int    `json:"NCPU"`
}

// Container represents a Docker container
type Container struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`
	State   string   `json:"State"`
	Status  string   `json:"Status"`
	Created int64    `json:"Created"`
}

// ContainerDetails for inspect response
type ContainerDetails struct {
	ID         string `json:"Id"`
	Name       string `json:"Name"`
	HostConfig struct {
		Privileged bool     `json:"Privileged"`
		Binds      []string `json:"Binds"`
		CapAdd     []string `json:"CapAdd"`
	} `json:"HostConfig"`
}

// Image represents a Docker image
type Image struct {
	ID       string   `json:"Id"`
	RepoTags []string `json:"RepoTags"`
	Size     int64    `json:"Size"`
	Created  int64    `json:"Created"`
}

// Finding represents a security finding
type Finding struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Severity    string                 `json:"severity"`
	Confidence  int                    `json:"confidence"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Remediation string                 `json:"remediation"`
	CWE         []string               `json:"cwe,omitempty"`
	CVSSScore   float64                `json:"cvss_score,omitempty"`
}

// Result is the output structure
type Result struct {
	Findings []Finding `json:"findings"`
}

// DockerClient wraps HTTP client for Docker API
type DockerClient struct {
	baseURL string
	client  *http.Client
}

// NewDockerClient creates a new Docker API client
func NewDockerClient(host string, port int) *DockerClient {
	return &DockerClient{
		baseURL: fmt.Sprintf("http://%s:%d", host, port),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Get performs a GET request to the Docker API
func (d *DockerClient) Get(path string) ([]byte, int, error) {
	resp, err := d.client.Get(d.baseURL + path)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return body, resp.StatusCode, nil
}

// CheckInfo retrieves Docker daemon info
func (d *DockerClient) CheckInfo() (*DockerInfo, error) {
	body, status, err := d.Get("/info")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("unexpected status: %d", status)
	}

	var info DockerInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// ListContainers retrieves all containers
func (d *DockerClient) ListContainers() ([]Container, error) {
	body, status, err := d.Get("/containers/json?all=true")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("unexpected status: %d", status)
	}

	var containers []Container
	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, err
	}

	return containers, nil
}

// InspectContainer gets container details
func (d *DockerClient) InspectContainer(id string) (*ContainerDetails, error) {
	body, status, err := d.Get(fmt.Sprintf("/containers/%s/json", id))
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("unexpected status: %d", status)
	}

	var details ContainerDetails
	if err := json.Unmarshal(body, &details); err != nil {
		return nil, err
	}

	return &details, nil
}

// ListImages retrieves all images
func (d *DockerClient) ListImages() ([]Image, error) {
	body, status, err := d.Get("/images/json")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("unexpected status: %d", status)
	}

	var images []Image
	if err := json.Unmarshal(body, &images); err != nil {
		return nil, err
	}

	return images, nil
}

func main() {
	// Get target from environment or defaults
	host := os.Getenv("CERT_X_GEN_TARGET_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	portStr := os.Getenv("CERT_X_GEN_TARGET_PORT")
	port := 2375
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	// Command line args override
	if len(os.Args) > 1 {
		host = os.Args[1]
	}
	if len(os.Args) > 2 {
		if p, err := strconv.Atoi(os.Args[2]); err == nil {
			port = p
		}
	}

	result := Result{Findings: []Finding{}}
	client := NewDockerClient(host, port)

	// Step 1: Check if Docker API responds
	info, err := client.CheckInfo()
	if err != nil {
		// Not a Docker API or not accessible
		outputJSON(result)
		return
	}

	evidence := map[string]interface{}{
		"docker_version":     info.ServerVersion,
		"api_version":        info.APIVersion,
		"os":                 info.OperatingSystem,
		"architecture":       info.Architecture,
		"containers_running": info.ContainersRunning,
		"containers_total":   info.Containers,
		"images":             info.Images,
		"cpu_count":          info.NCPU,
		"memory_total_mb":    info.MemTotal / 1024 / 1024,
	}

	// Step 2: List containers
	containers, err := client.ListContainers()
	if err == nil {
		evidence["container_count"] = len(containers)

		// Check for privileged containers
		var privilegedContainers []string
		var containerNames []string

		for i, c := range containers {
			if i >= 10 {
				break // Sample first 10
			}

			name := "unknown"
			if len(c.Names) > 0 {
				name = strings.TrimPrefix(c.Names[0], "/")
			}
			containerNames = append(containerNames, name)

			// Inspect for privileged mode
			details, err := client.InspectContainer(c.ID[:12])
			if err == nil && details.HostConfig.Privileged {
				privilegedContainers = append(privilegedContainers, name)
			}
		}

		evidence["container_names"] = containerNames
		if len(privilegedContainers) > 0 {
			evidence["privileged_containers"] = privilegedContainers
		}
	}

	// Step 3: List images
	images, err := client.ListImages()
	if err == nil {
		var imageList []string
		for i, img := range images {
			if i >= 10 {
				break
			}
			if len(img.RepoTags) > 0 && img.RepoTags[0] != "<none>:<none>" {
				imageList = append(imageList, img.RepoTags[0])
			}
		}
		evidence["image_list"] = imageList
	}

	// Build description
	desc := fmt.Sprintf("Docker API is exposed without authentication on %s:%d. ", host, port)
	desc += fmt.Sprintf("Docker version: %s. ", info.ServerVersion)
	desc += fmt.Sprintf("Running containers: %d/%d. ", info.ContainersRunning, info.Containers)

	if privContainers, ok := evidence["privileged_containers"].([]string); ok && len(privContainers) > 0 {
		desc += fmt.Sprintf("PRIVILEGED CONTAINERS FOUND: %s. ", strings.Join(privContainers, ", "))
	}

	desc += "An attacker can create privileged containers, mount host filesystem, and achieve full host compromise."

	finding := Finding{
		ID:          "docker-api-unauth",
		Name:        "Docker API Unauthenticated Access",
		Severity:    "critical",
		Confidence:  98,
		Description: desc,
		Evidence:    evidence,
		Remediation: "Disable TCP socket exposure or enable TLS mutual authentication. Never expose port 2375 to untrusted networks. Use Docker context with SSH for remote management.",
		CWE:         []string{"CWE-306"},
		CVSSScore:   9.8,
	}

	result.Findings = append(result.Findings, finding)
	outputJSON(result)
}

func outputJSON(result Result) {
	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}
