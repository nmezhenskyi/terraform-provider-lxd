package auth

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"
)

func TestPermissionModel_RoundTrip(t *testing.T) {
	ctx := t.Context()

	var tests = []struct {
		Name        string
		Entitlement string
		EntityType  string
		EntityArgs  map[string]string
		ExpectURL   string
		ExpectError string
	}{
		{
			Name:        "Server",
			Entitlement: "admin",
			EntityType:  "server",
			ExpectURL:   "/1.0",
		},
		{
			Name:        "Instance",
			Entitlement: "can_view",
			EntityType:  "instance",
			EntityArgs: map[string]string{
				"name":    "c1",
				"project": "myproj",
			},
			ExpectURL: "/1.0/instances/c1?project=myproj",
		},
		{
			Name:        "Instance",
			Entitlement: "can_view",
			EntityType:  "instance",
			EntityArgs: map[string]string{
				"name": "c1",
			},
			ExpectError: `Permission argument "project" is required`,
		},
		{
			Name:        "Storage volume",
			Entitlement: "can_view",
			EntityType:  "storage_volume",
			EntityArgs: map[string]string{
				"name":     "vol1",
				"pool":     "pool1",
				"type":     "custom",
				"project":  "default",
				"location": "loc1",
			},
			ExpectURL: "/1.0/storage-pools/pool1/volumes/custom/vol1?project=default&target=loc1",
		},
		{
			Name:        "Invalid argument",
			Entitlement: "can_view",
			EntityType:  "storage_volume",
			EntityArgs: map[string]string{
				"name":    "vol1",
				"type":    "custom",
				"pool":    "pool1",
				"project": "default",
				"extra":   "value",
			},
			ExpectError: "Unknown path argument \"extra\"",
		},
		{
			Name:        "Do not allow project argument for project entity type",
			Entitlement: "can_view",
			EntityType:  "project",
			EntityArgs: map[string]string{
				"name":    "vol1",
				"project": "default",
			},
			ExpectError: `Permission argument "project" is not allowed`,
		},
		{
			Name:        "Do not allow project argument for server entity type",
			Entitlement: "admin",
			EntityType:  "server",
			EntityArgs: map[string]string{
				"project": "default",
			},
			ExpectError: `Permission argument "project" is not allowed`,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			model := mustPermissionModel(t, test.Entitlement, test.EntityType, test.EntityArgs)

			apiPerm, err := model.ToAPI(ctx)
			if test.ExpectError != "" {
				require.Errorf(t, err, "Expected error %q but got no error", test.ExpectError)
				require.Contains(t, err.Error(), test.ExpectError)
				return
			}

			require.NoError(t, err, "Unexpected error converting model to API permission")
			require.Equal(t, model.Entitlement.ValueString(), apiPerm.Entitlement, "Entitlement mismatch in API permission")
			require.Equal(t, model.EntityType.ValueString(), apiPerm.EntityType, "EntityType mismatch in API permission")
			require.Equal(t, test.ExpectURL, apiPerm.EntityReference, "EntityReference does not match expected URL")

			modelPerm, err := PermissionFromAPI(ctx, *apiPerm)
			require.NoError(t, err, "Unexpected error converting API permission back to model")
			require.Equal(t, model.Entitlement.ValueString(), modelPerm.Entitlement.ValueString(), "Entitlement mismatch after round trip")
			require.Equal(t, model.EntityType.ValueString(), modelPerm.EntityType.ValueString(), "EntityType mismatch after round trip")
			require.Equal(t, mustMap(t, model.EntityArgs), mustMap(t, modelPerm.EntityArgs), "EntityArgs mismatch after round trip")
		})
	}
}

func mustPermissionModel(t *testing.T, entitlement, entityType string, args map[string]string) PermissionModel {
	t.Helper()
	argsMapType, diags := types.MapValueFrom(context.Background(), types.StringType, args)
	if diags.HasError() {
		t.Fatalf("Failed building arguments map: %v", diags)
	}

	return PermissionModel{
		Entitlement: types.StringValue(entitlement),
		EntityType:  types.StringValue(entityType),
		EntityArgs:  argsMapType,
	}
}

func mustMap(t *testing.T, m types.Map) map[string]string {
	t.Helper()
	out := map[string]string{}
	if m.IsNull() || m.IsUnknown() {
		return out
	}
	diags := m.ElementsAs(context.Background(), &out, false)
	if diags.HasError() {
		t.Fatalf("Failed ElementsAs: %v", diags)
	}
	return out
}
