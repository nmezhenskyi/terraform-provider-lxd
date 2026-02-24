package auth

import (
	"context"
	"fmt"
	"maps"
	"net/url"

	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/entity"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/terraform-lxd/terraform-provider-lxd/internal/common"
)

// PermissionModel represents a permission entry within an auth group.
type PermissionModel struct {
	Entitlement types.String `tfsdk:"entitlement"`
	EntityType  types.String `tfsdk:"entity_type"`
	EntityArgs  types.Map    `tfsdk:"entity_args"`
}

var PermissionModelType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"entitlement": types.StringType,
		"entity_type": types.StringType,
		"entity_args": types.MapType{ElemType: types.StringType},
	},
}

// ToAPI converts the [PermissionModel] to the [api.Permission].
func (p PermissionModel) ToAPI(ctx context.Context) (*api.Permission, error) {
	entitlement := p.Entitlement.ValueString()
	entityType := entity.Type(p.EntityType.ValueString())

	args, diags := common.FromMapType[string](ctx, p.EntityArgs)
	if diags.HasError() {
		return nil, fmt.Errorf("Failed to convert permission arguments: %v", diags.Errors())
	}

	project := args["project"]
	location := args["location"]
	delete(args, "project")
	delete(args, "location")

	entityURL, err := entityType.URLFromNamedArgs(project, location, args)
	if err != nil {
		return nil, err
	}

	// To prevent state mismatch, we need to track the project if it is required for a given
	// entity type because it will be included in the resulting URL. Therefore, error out if
	// the project was not set, but is present in the resulting URL.
	if project == "" && entityURL.Query().Has("project") {
		return nil, fmt.Errorf(`Permission argument "project" is required for permission with entity type %q`, entityType)
	}

	if project != "" && !entityURL.Query().Has("project") {
		return nil, fmt.Errorf(`Permission argument "project" is not allowed for permission with entity type %q`, entityType)
	}

	return &api.Permission{
		Entitlement:     entitlement,
		EntityType:      string(entityType),
		EntityReference: entityURL.String(),
	}, nil
}

// PermissionFromAPI converts an [api.Permission] to a [PermissionModel].
func PermissionFromAPI(ctx context.Context, p api.Permission) (*PermissionModel, error) {
	url, err := url.Parse(p.EntityReference)
	if err != nil {
		return nil, fmt.Errorf("Invalid entity reference URL %q for permission: %w", p.EntityReference, err)
	}

	entityType, project, location, pathArgs, err := entity.ParseURLWithNamedArgs(*url)
	if err != nil {
		return nil, fmt.Errorf("Failed parsing entity reference URL %q for permission: %w", p.EntityReference, err)
	}

	args := make(map[string]string, len(pathArgs)+2)
	maps.Copy(args, pathArgs)

	// Ignore project for entity type "project" because it is already included
	// in the "name" field. This is exception where project is returned despite
	// not being included in the URL query parameters.
	if entityType != entity.TypeProject {
		args["project"] = project
	}

	args["location"] = location

	// Remove empty arguments to prevent spurious differences in state.
	for k, v := range args {
		if v == "" {
			delete(args, k)
		}
	}

	argsMapType, diags := types.MapValueFrom(ctx, types.StringType, args)
	if diags.HasError() {
		return nil, fmt.Errorf("Failed to convert arguments to map for permission with entity URL %q: %v", p.EntityReference, diags.Errors())
	}

	return &PermissionModel{
		Entitlement: types.StringValue(p.Entitlement),
		EntityType:  types.StringValue(string(entityType)),
		EntityArgs:  argsMapType,
	}, nil
}

// PermissionsToAPI converts a slice of [PermissionModel] to a slice of [api.Permission].
func PermissionsToAPI(perms []PermissionModel) ([]api.Permission, error) {
	permissions := make([]api.Permission, 0, len(perms))
	for _, perm := range perms {
		apiPerm, err := perm.ToAPI(context.Background())
		if err != nil {
			return nil, err
		}

		permissions = append(permissions, *apiPerm)
	}

	return permissions, nil
}

// PermissionsFromAPI converts a slice of [api.Permission] to a slice of [PermissionModel].
func PermissionsFromAPI(ctx context.Context, apiPerms []api.Permission) ([]PermissionModel, error) {
	permissions := make([]PermissionModel, 0, len(apiPerms))
	for _, apiPerm := range apiPerms {
		perm, err := PermissionFromAPI(ctx, apiPerm)
		if err != nil {
			return nil, err
		}

		permissions = append(permissions, *perm)
	}

	return permissions, nil
}
