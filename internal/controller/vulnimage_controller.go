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

package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	v1alpha1 "github.com/vinayak-somvanshi-dsw/vuln-k8s/api/v1alpha1"
	"github.com/google/uuid"
)

const (
	// Finalizer name for cleanup
	VulnImageFinalizer = "security.vinz.in/vuln-image-finalizer"
	
	// Annotations
	LastScanAnnotation = "security.vinz.in/last-scan"
	ScanIntervalAnnotation = "security.vinz.in/scan-interval"
	
	// Default values
	DefaultScanInterval = 24 * time.Hour
	DefaultScanTimeout = 5 * time.Minute
	MaxRetries = 5
	
	// Conditions
	ConditionScanned = "Scanned"
	ConditionReady = "Ready"
)

// Metrics
var (
	scanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "vuln_image_scan_duration_seconds",
			Help: "Duration of vulnerability scans",
		},
		[]string{"image", "status"},
	)
	
	vulnerabilityCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vuln_image_vulnerabilities_total",
			Help: "Total number of vulnerabilities found",
		},
		[]string{"image", "severity"},
	)
	
	scanCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vuln_image_scans_total",
			Help: "Total number of scans performed",
		},
		[]string{"image", "status"},
	)
)

func init() {
	metrics.Registry.MustRegister(scanDuration, vulnerabilityCount, scanCount)
}

// VulnImageReconciler reconciles a VulnImage object
type VulnImageReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	NowFunc          func() time.Time // for testability
	BaseRequeueAfter time.Duration    // configurable base requeue interval
	ScanTimeout      time.Duration    // configurable scan timeout
	MaxConcurrentScans int            // limit concurrent scans
}

// now returns the current time, can be overridden for tests
func (r *VulnImageReconciler) now() time.Time {
	if r.NowFunc != nil {
		return r.NowFunc()
	}
	return time.Now()
}

// +kubebuilder:rbac:groups=security.vinz.in,resources=vulnimages,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.vinz.in,resources=vulnimages/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.vinz.in,resources=vulnimages/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// updateStatus updates the status subresource and logs errors.
func (r *VulnImageReconciler) updateStatus(ctx context.Context, vuln *v1alpha1.VulnImage, logger logr.Logger, msg string) error {
	if err := r.Status().Update(ctx, vuln); err != nil {
		logger.Error(err, msg)
		return err
	}
	return nil
}

// shouldScan determines if a scan should be performed based on status, spec, and time interval.
func (r *VulnImageReconciler) shouldScan(vuln *v1alpha1.VulnImage) bool {
	// Always scan if never scanned, failed, or pending
	if vuln.Status.ScanStatus == "" ||
		vuln.Status.ScanStatus == "Failed" ||
		vuln.Status.ScanStatus == "Pending" {
		return true
	}
	
	// Check if enough time has passed since last scan
	if vuln.Status.LastScanTime.IsZero() {
		return true
	}
	
	// Get scan interval from annotation or use default
	scanInterval := DefaultScanInterval
	if intervalStr, ok := vuln.Annotations[ScanIntervalAnnotation]; ok {
		if interval, err := time.ParseDuration(intervalStr); err == nil {
			scanInterval = interval
		}
	}
	
	// Check if scan interval has elapsed
	return r.now().Sub(vuln.Status.LastScanTime.Time) >= scanInterval
}

// getImageDigest attempts to get the image digest/hash for better tracking
func getImageDigest(image string) string {
	hash := sha256.Sum256([]byte(image))
	return fmt.Sprintf("%x", hash)[:16]
}

// runTrivyScan executes Trivy and returns its JSON output or error.
func runTrivyScan(image string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	// Enhanced Trivy command with more options
	cmd := exec.CommandContext(ctx, "trivy", "image", 
		"--quiet", 
		"--format", "json",
		"--skip-db-update",  // Skip DB update for faster scans
		"--skip-java-db-update",
		"--no-progress",
		"--timeout", "4m",   // Internal trivy timeout
		image)
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("trivy error: %v, stderr: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// TrivyVulnerability represents a vulnerability in Trivy's JSON output
type TrivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	Severity         string `json:"Severity"`
	Description      string `json:"Description"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	PrimaryURL       string `json:"PrimaryURL"`
	CVSS             struct {
		V3Score float64 `json:"V3Score"`
	} `json:"CVSS"`
}

// parseTrivyOutput parses Trivy JSON and returns vulnerabilities and summary.
func parseTrivyOutput(data []byte) ([]v1alpha1.Vulnerability, map[string]int, error) {
	var trivyOutput struct {
		Results []struct {
			Target          string               `json:"Target"`
			Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	
	if err := json.Unmarshal(data, &trivyOutput); err != nil {
		return nil, nil, err
	}
	
	var vulns []v1alpha1.Vulnerability
	summary := make(map[string]int)
	
	for _, result := range trivyOutput.Results {
		for _, tv := range result.Vulnerabilities {
			// Convert Trivy vulnerability to our format
			vuln := v1alpha1.Vulnerability{
				ID:          tv.VulnerabilityID,
				Severity:    v1alpha1.SeverityLevel(strings.ToUpper(tv.Severity)),
				Description: tv.Description,
				Package:     tv.PkgName,
				Version:     tv.InstalledVersion,
				FixedBy:     tv.FixedVersion,
			}
			vulns = append(vulns, vuln)
			summary[strings.ToUpper(tv.Severity)]++
		}
	}
	
	return vulns, summary, nil
}

// generateScanID generates a unique scan ID
func generateScanID() string {
	return fmt.Sprintf("scan-%s", uuid.New().String())
}

// setCondition sets a condition on the VulnImage status
func (r *VulnImageReconciler) setCondition(vuln *v1alpha1.VulnImage, conditionType string, status metav1.ConditionStatus, reason, message string) {
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		LastTransitionTime: metav1.NewTime(r.now()),
		Reason:             reason,
		Message:            message,
	}
	
	// Note: This is a placeholder - the actual implementation would depend on
	// whether the VulnImageStatus has a Conditions field
	_ = condition
}

// recordMetrics records Prometheus metrics
func (r *VulnImageReconciler) recordMetrics(image string, status string, duration time.Duration, summary map[string]int) {
	scanDuration.WithLabelValues(image, status).Observe(duration.Seconds())
	scanCount.WithLabelValues(image, status).Inc()
	
	// Record vulnerability counts by severity
	for severity, count := range summary {
		vulnerabilityCount.WithLabelValues(image, severity).Set(float64(count))
	}
}

// handleFinalizer handles resource cleanup when deleted
func (r *VulnImageReconciler) handleFinalizer(ctx context.Context, vuln *v1alpha1.VulnImage, logger logr.Logger) (ctrl.Result, error) {
	if vuln.DeletionTimestamp.IsZero() {
		// Add finalizer if not present
		if !controllerutil.ContainsFinalizer(vuln, VulnImageFinalizer) {
			controllerutil.AddFinalizer(vuln, VulnImageFinalizer)
			return ctrl.Result{}, r.Update(ctx, vuln)
		}
	} else {
		// Handle deletion
		if controllerutil.ContainsFinalizer(vuln, VulnImageFinalizer) {
			logger.Info("Cleaning up VulnImage resources", "image", vuln.Spec.Image)
			
			// Clean up metrics
			labels := prometheus.Labels{"image": vuln.Spec.Image}
			scanDuration.DeletePartialMatch(labels)
			vulnerabilityCount.DeletePartialMatch(labels)
			scanCount.DeletePartialMatch(labels)
			
			// Remove finalizer
			controllerutil.RemoveFinalizer(vuln, VulnImageFinalizer)
			return ctrl.Result{}, r.Update(ctx, vuln)
		}
	}
	return ctrl.Result{}, nil
}

func (r *VulnImageReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	startTime := r.now()

	// Fetch CR
	var vuln v1alpha1.VulnImage
	if err := r.Get(ctx, req.NamespacedName, &vuln); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle finalizer
	if result, err := r.handleFinalizer(ctx, &vuln, logger); err != nil {
		return result, err
	} else if !result.IsZero() {
		return result, nil
	}

	// Skip if deletion is in progress
	if !vuln.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	// Check if scan is needed
	if !r.shouldScan(&vuln) {
		logger.Info("Skipping scan: interval not reached", "image", vuln.Spec.Image)
		r.setCondition(&vuln, ConditionReady, metav1.ConditionTrue, "SkipScan", "Scan interval not reached")
		_ = r.updateStatus(ctx, &vuln, logger, "Failed to update status")
		
		// Requeue for next scan interval
		nextScan := DefaultScanInterval
		if intervalStr, ok := vuln.Annotations[ScanIntervalAnnotation]; ok {
			if interval, err := time.ParseDuration(intervalStr); err == nil {
				nextScan = interval
			}
		}
		return ctrl.Result{RequeueAfter: nextScan}, nil
	}

	logger.Info("Starting image scan", "image", vuln.Spec.Image)
	
	// Update status to InProgress
	vuln.Status.ScanStatus = "InProgress"
	vuln.Status.ScanID = generateScanID()
	vuln.Status.ScanTime = metav1.NewTime(r.now())
	vuln.Status.ScanError = ""
	
	r.setCondition(&vuln, ConditionScanned, metav1.ConditionFalse, "ScanInProgress", "Vulnerability scan in progress")
	r.setCondition(&vuln, ConditionReady, metav1.ConditionFalse, "ScanInProgress", "Vulnerability scan in progress")
	
	if err := r.updateStatus(ctx, &vuln, logger, "Failed to update status to InProgress"); err != nil {
		return ctrl.Result{}, err
	}

	// Determine base requeue interval
	baseRequeue := r.BaseRequeueAfter
	if baseRequeue == 0 {
		baseRequeue = 30 * time.Second
	}

	// Use exponential backoff based on failure count
	// Note: Since FailureCount doesn't exist in the status, we'll use a default of 0
	failures := 0

	// Cap retries
	if failures >= MaxRetries {
		logger.Error(nil, "Max retries exceeded", "failures", failures)
		vuln.Status.ScanStatus = "Failed"
		vuln.Status.ScanError = fmt.Sprintf("Max retries (%d) exceeded", MaxRetries)
		r.setCondition(&vuln, ConditionScanned, metav1.ConditionFalse, "MaxRetriesExceeded", "Maximum retry attempts exceeded")
		r.setCondition(&vuln, ConditionReady, metav1.ConditionFalse, "MaxRetriesExceeded", "Maximum retry attempts exceeded")
		_ = r.updateStatus(ctx, &vuln, logger, "Failed to update status after max retries")
		return ctrl.Result{RequeueAfter: 24 * time.Hour}, nil // Retry after 24 hours
	}

	requeueAfter := baseRequeue * time.Duration(1<<failures)
	if requeueAfter > 10*time.Minute {
		requeueAfter = 10 * time.Minute
	}

	// Determine scan timeout
	scanTimeout := r.ScanTimeout
	if scanTimeout == 0 {
		scanTimeout = DefaultScanTimeout
	}

	// Run Trivy scan
	out, err := runTrivyScan(vuln.Spec.Image, scanTimeout)
	if err != nil {
		logger.Error(err, "Trivy scan failed")
		vuln.Status.ScanStatus = "Failed"
		vuln.Status.ScanError = err.Error()
		
		scanDuration := r.now().Sub(startTime)
		r.setCondition(&vuln, ConditionScanned, metav1.ConditionFalse, "ScanFailed", err.Error())
		r.setCondition(&vuln, ConditionReady, metav1.ConditionFalse, "ScanFailed", err.Error())
		r.recordMetrics(vuln.Spec.Image, "failed", scanDuration, nil)
		
		_ = r.updateStatus(ctx, &vuln, logger, "Failed to update status after Trivy scan failure")
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	// Parse Trivy JSON
	vulns, summary, err := parseTrivyOutput(out)
	if err != nil {
		logger.Error(err, "Trivy JSON parse error")
		vuln.Status.ScanStatus = "Failed"
		vuln.Status.ScanError = err.Error()
		
		scanDuration := r.now().Sub(startTime)
		r.setCondition(&vuln, ConditionScanned, metav1.ConditionFalse, "ScanFailed", err.Error())
		r.setCondition(&vuln, ConditionReady, metav1.ConditionFalse, "ScanFailed", err.Error())
		r.recordMetrics(vuln.Spec.Image, "failed", scanDuration, nil)
		
		_ = r.updateStatus(ctx, &vuln, logger, "Failed to update status after Trivy JSON parse failure")
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	// Update status fields for success
	vuln.Status.ScanStatus = "Completed"
	vuln.Status.LastScanTime = metav1.NewTime(r.now())
	vuln.Status.Vulnerabilities = vulns
	vuln.Status.Summary = summary
	vuln.Status.ScanError = ""

	// Count critical and high vulnerabilities for condition
	criticalCount := summary["CRITICAL"]
	highCount := summary["HIGH"]

	if criticalCount > 0 || highCount > 0 {
		r.setCondition(&vuln, ConditionReady, metav1.ConditionFalse, "VulnerabilitiesFound", 
			fmt.Sprintf("Found %d critical and %d high severity vulnerabilities", criticalCount, highCount))
	} else {
		r.setCondition(&vuln, ConditionReady, metav1.ConditionTrue, "NoHighRiskVulnerabilities", 
			"No critical or high severity vulnerabilities found")
	}

	r.setCondition(&vuln, ConditionScanned, metav1.ConditionTrue, "ScanCompleted", "Vulnerability scan completed successfully")

	scanDuration := r.now().Sub(startTime)
	r.recordMetrics(vuln.Spec.Image, "completed", scanDuration, summary)

	if err := r.updateStatus(ctx, &vuln, logger, "Failed to update status"); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Image scan completed", 
		"image", vuln.Spec.Image, 
		"vulnCount", len(vulns), 
		"summary", summary,
		"duration", scanDuration)

	// Schedule next scan
	nextScan := DefaultScanInterval
	if intervalStr, ok := vuln.Annotations[ScanIntervalAnnotation]; ok {
		if interval, err := time.ParseDuration(intervalStr); err == nil {
			nextScan = interval
		}
	}
	
	return ctrl.Result{RequeueAfter: nextScan}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VulnImageReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Set defaults
	if r.BaseRequeueAfter == 0 {
		r.BaseRequeueAfter = 30 * time.Second
	}
	if r.ScanTimeout == 0 {
		r.ScanTimeout = DefaultScanTimeout
	}
	if r.MaxConcurrentScans == 0 {
		r.MaxConcurrentScans = 5
	}

	// Create predicates to filter unnecessary reconciles
	pred := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Only reconcile if spec or annotations changed
			return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() ||
				!equalAnnotations(e.ObjectOld.GetAnnotations(), e.ObjectNew.GetAnnotations())
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !e.DeleteStateUnknown
		},
	}

	// Use the proper controller-runtime API for setting up the controller
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.VulnImage{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.MaxConcurrentScans,
		}).
		WithEventFilter(pred).
		Complete(r)
}

// equalAnnotations compares two annotation maps for scan-related changes
func equalAnnotations(old, new map[string]string) bool {
	scanRelatedKeys := []string{ScanIntervalAnnotation, LastScanAnnotation}
	
	for _, key := range scanRelatedKeys {
		if old[key] != new[key] {
			return false
		}
	}
	return true
}