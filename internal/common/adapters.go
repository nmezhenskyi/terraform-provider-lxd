package common

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func FromMapType[T any](ctx context.Context, m types.Map) (map[string]T, diag.Diagnostics) {
	if m.IsNull() || m.IsUnknown() {
		return make(map[string]T), nil
	}

	items := make(map[string]T, len(m.Elements()))
	diags := m.ElementsAs(ctx, &items, false)
	if diags.HasError() {
		return nil, diags
	}

	return items, diags
}

func FromSetType[T any](ctx context.Context, set types.Set) ([]T, diag.Diagnostics) {
	if set.IsNull() || set.IsUnknown() {
		return make([]T, 0), nil
	}

	items := make([]T, 0, len(set.Elements()))
	diags := set.ElementsAs(ctx, &items, false)
	if diags.HasError() {
		return nil, diags
	}

	return items, diags
}

func ToStringSetType(ctx context.Context, items []string) (types.Set, diag.Diagnostics) {
	if items == nil {
		return types.SetNull(types.StringType), nil
	}

	values := make([]attr.Value, 0, len(items))
	for _, s := range items {
		values = append(values, types.StringValue(s))
	}

	return types.SetValue(types.StringType, values)
}
