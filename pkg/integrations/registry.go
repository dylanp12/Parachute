package integrations

import "sort"

// Registry maps provider names to their RouteClassifier implementations.
// It is the central dispatch point for multi-provider route classification.
type Registry struct {
	classifiers map[string]RouteClassifier
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		classifiers: make(map[string]RouteClassifier),
	}
}

// Register adds a RouteClassifier to the registry, keyed by its Provider() name.
func (r *Registry) Register(c RouteClassifier) {
	r.classifiers[c.Provider()] = c
}

// Get returns the RouteClassifier for the given provider name.
func (r *Registry) Get(provider string) (RouteClassifier, bool) {
	c, ok := r.classifiers[provider]
	return c, ok
}

// Providers returns a sorted list of registered provider names.
func (r *Registry) Providers() []string {
	names := make([]string, 0, len(r.classifiers))
	for name := range r.classifiers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ClassifyForProvider classifies a request for the given provider.
// Returns "unknown" if the provider is not registered.
func (r *Registry) ClassifyForProvider(provider, method, path string) string {
	c, ok := r.classifiers[provider]
	if !ok {
		return "unknown"
	}
	return c.Classify(method, path)
}
