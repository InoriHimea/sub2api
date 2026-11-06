package adminaccess

import "testing"

func TestUsageHourlyPermissionIsolation(t *testing.T) {
	hourly := Policy{GlobalPermissions: []string{"usage.hourly.read"}}
	if err := ValidatePolicy(hourly); err != nil {
		t.Fatal(err)
	}
	if !RouteAllowed(hourly, "GET", "/api/v1/admin/usage/hourly") {
		t.Fatal("explicit hourly permission must allow aggregates")
	}
	for _, policy := range []Policy{{}, {GlobalPermissions: []string{"usage.read"}}, {GlobalPermissions: []string{"dashboard.read"}}} {
		if RouteAllowed(policy, "GET", "/api/v1/admin/usage/hourly") {
			t.Fatal("existing permissions must not silently gain the new endpoint")
		}
	}
	for _, path := range []string{"/api/v1/admin/usage", "/api/v1/admin/usage/stats", "/api/v1/admin/users", "/api/v1/admin/users/:id/usage"} {
		if RouteAllowed(hourly, "GET", path) {
			t.Fatalf("hourly-only reader gained details: %s", path)
		}
	}
	if RouteAllowed(hourly, "POST", "/api/v1/admin/usage/hourly") {
		t.Fatal("hourly-only reader gained a write method")
	}
}
