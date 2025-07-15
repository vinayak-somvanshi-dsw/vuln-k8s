/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VulnImageSpec defines the desired state of VulnImage.
type VulnImageSpec struct {
	Image string `json:"image,omitempty"` // Image is the container image to be scanned for vulnerabilities.
}

// VulnImageStatus defines the observed state of VulnImage.
type VulnImageStatus struct {
	ScanStatus    string            `json:"scanStatus,omitempty"` // ScanStatus can be "Pending", "InProgress", "Completed", or "Failed".
	ScanID        string            `json:"scanID,omitempty"`     // ScanID is a unique identifier for the scan operation, useful for tracking.
	ScanTime      metav1.Time       `json:"scanTime,omitempty"`   // ScanTime indicates when the scan was initiated.
	LastScanTime  metav1.Time       `json:"lastScanTime,omitempty"` // LastScanTime indicates when the last scan was performed.
	ScanError     string            `json:"scanError,omitempty"`  // ScanError contains error details if the scan fails.
	Summary       map[SeverityLevel]int `json:"summary,omitempty"` // Summary maps severity levels to the count of vulnerabilities, e.g., {"CRITICAL": 2, "HIGH": 1}.
}

// SeverityLevel defines the severity of a vulnerability.
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "CRITICAL"
	SeverityHigh     SeverityLevel = "HIGH"
	SeverityMedium   SeverityLevel = "MEDIUM"
	SeverityLow      SeverityLevel = "LOW"
	SeverityUnknown  SeverityLevel = "UNKNOWN"
)

// Vulnerability represents a single vulnerability found in an image.
type Vulnerability struct {
	ID          string        `json:"id,omitempty"`          // Unique identifier for the vulnerability (e.g., CVE ID)
	Severity    SeverityLevel `json:"severity,omitempty"`    // Severity level (e.g., CRITICAL, HIGH, MEDIUM, LOW)
	Description string        `json:"description,omitempty"` // Description of the vulnerability
	Package     string        `json:"package,omitempty"`     // Affected package name
	Version     string        `json:"version,omitempty"`     // Affected package version
	FixedBy     string        `json:"fixedBy,omitempty"`     // Version in which the vulnerability is fixed, if available
}
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VulnImage is the Schema for the vulnimages API.
type VulnImage struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VulnImageSpec   `json:"spec,omitempty"`
	Status VulnImageStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VulnImageList contains a list of VulnImage.
type VulnImageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VulnImage `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VulnImage{}, &VulnImageList{})
}
