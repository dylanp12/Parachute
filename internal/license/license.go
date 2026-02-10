package license

import "errors"

// ErrNoLicense is returned when a Pro feature is requested without a license
var ErrNoLicense = errors.New("this feature requires a Parachute Pro license")

// Feature represents a gatable Pro/Enterprise feature
type Feature string

const (
	FeatureCloudRelay    Feature = "cloud_relay"
	FeatureFleetDashboard Feature = "fleet_dashboard"
	FeatureSIEM          Feature = "siem_export"
	FeatureCentralPolicy Feature = "central_policy"
	FeatureRBAC          Feature = "rbac"
	FeatureCompliance    Feature = "compliance_reports"
)

// Validator checks if Pro/Enterprise features are enabled
type Validator interface {
	// IsEnabled returns true if the given feature is available
	IsEnabled(feature Feature) bool
	// Validate checks if the license key is valid
	Validate(key string) error
}
