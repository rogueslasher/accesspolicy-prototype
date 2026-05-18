package accesspolicy

import (
	"testing"

	agenticv1alpha1 "github.com/rogueslasher/accesspolicy-prototype/api/agentic/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestBuildAuthPolicy(t *testing.T) {
	r := &AccessPolicyReconciler{}
	backendName := gwapiv1.ObjectName("test-backend")

	policy := &agenticv1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: agenticv1alpha1.AccessPolicySpec{
			TargetRefs: []gwapiv1.LocalPolicyTargetReference{
				{Name: backendName},
			},
			Rules: []agenticv1alpha1.AccessRule{
				{
					Source: agenticv1alpha1.Source{
						Type: agenticv1alpha1.SourceTypeOIDC,
						OIDC: &agenticv1alpha1.OIDCSource{
							Issuer: "https://auth.example.com",
							Claims: map[string]string{"role": "admin"},
						},
					},
					Tools: []string{"add", "subtract"},
				},
			},
		},
	}

	authPolicy := r.buildAuthPolicy(policy)

	if authPolicy == nil {
		t.Fatal("Expected AuthPolicy to be generated, got nil")
	}

	if authPolicy.Name != "ap-generated-test-policy" {
		t.Errorf("Expected name 'ap-generated-test-policy', got %s", authPolicy.Name)
	}

	identity, ok := authPolicy.Spec.AuthScheme.Identity["oidc-source-0"]
	if !ok || identity.OIDC.Endpoint != "https://auth.example.com" {
		t.Errorf("Expected OIDC endpoint 'https://auth.example.com', got %+v", identity)
	}

	rule, ok := authPolicy.Spec.AuthScheme.Authorization["access-rule-0"]
	if !ok {
		t.Fatal("Expected access-rule-0 to be present")
	}

	patterns := rule.PatternMatching.Patterns
	if len(patterns) != 2 {
		t.Fatalf("Expected 2 patterns, got %d", len(patterns))
	}

	expectedCEL := "request.headers['x-mcp-toolname'] in ['add', 'subtract']"
	if patterns[0].Predicate != expectedCEL {
		t.Errorf("Expected CEL predicate %q, got %q", expectedCEL, patterns[0].Predicate)
	}

	if patterns[1].Selector != "auth.identity.role" || patterns[1].Value != "admin" {
		t.Errorf("Expected role=admin check, got %+v", patterns[1])
	}
}
