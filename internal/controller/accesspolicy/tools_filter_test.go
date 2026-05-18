package accesspolicy

import (
	"context"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"k8s.io/apimachinery/pkg/runtime"

	agenticv1alpha1 "github.com/rogueslasher/accesspolicy-prototype/api/agentic/v1alpha1"
	"github.com/mark3labs/mcp-go/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestFilterToolsList(t *testing.T) {
	scheme := runtime.NewScheme()
	agenticv1alpha1.AddToScheme(scheme)

	backendName := gwapiv1.ObjectName("test-backend")

	policy := &agenticv1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: agenticv1alpha1.AccessPolicySpec{
			TargetRefs: []gwapiv1.LocalPolicyTargetReference{{Name: backendName}},
			Rules: []agenticv1alpha1.AccessRule{
				{
					Source: agenticv1alpha1.Source{
						Type: agenticv1alpha1.SourceTypeOIDC,
						OIDC: &agenticv1alpha1.OIDCSource{
							Issuer: "https://auth.example.com",
							Claims: map[string]string{"role": "admin"},
						},
					},
					Tools: []string{"add", "subtract"}, // cannot use divide
				},
				{
					Source: agenticv1alpha1.Source{
						Type: agenticv1alpha1.SourceTypeOIDC,
						OIDC: &agenticv1alpha1.OIDCSource{
							Issuer: "https://auth.example.com",
							Claims: map[string]string{"role": "superuser"},
						},
					},
					Tools: []string{}, // empty means all tools
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()
	filter := NewToolsFilter(fakeClient, "default")

	allTools := []mcp.Tool{
		{Name: "add"},
		{Name: "subtract"},
		{Name: "divide"},
	}

	tests := []struct {
		name          string
		caller        CallerIdentity
		expectedCount int
	}{
		{
			name: "Admin role gets filtered tools",
			caller: CallerIdentity{
				Issuer: "https://auth.example.com",
				Claims: map[string]string{"role": "admin"},
			},
			expectedCount: 2, // add, subtract
		},
		{
			name: "Superuser gets all tools",
			caller: CallerIdentity{
				Issuer: "https://auth.example.com",
				Claims: map[string]string{"role": "superuser"},
			},
			expectedCount: 3, // all
		},
		{
			name: "Unknown user gets no tools",
			caller: CallerIdentity{
				Issuer: "https://auth.example.com",
				Claims: map[string]string{"role": "nobody"},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := filter.FilterToolsList(context.Background(), allTools, tt.caller, "test-backend")
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(filtered) != tt.expectedCount {
				t.Errorf("Expected %d tools, got %d", tt.expectedCount, len(filtered))
			}
		})
	}
}
