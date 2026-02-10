//go:build !pro

package license

// OpenSourceValidator is the default validator for the open-source build.
// All Pro features return false. The closed-source repo provides a
// ProValidator via license_pro.go with the "pro" build tag.
type OpenSourceValidator struct{}

// NewValidator creates the default open-source license validator
func NewValidator() Validator {
	return &OpenSourceValidator{}
}

// IsEnabled always returns false in the open-source build
func (v *OpenSourceValidator) IsEnabled(feature Feature) bool {
	return false
}

// Validate always returns ErrNoLicense in the open-source build
func (v *OpenSourceValidator) Validate(key string) error {
	return ErrNoLicense
}
