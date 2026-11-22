package webapp

import "testing"

func TestPortalsShareOriginHostAndSeparateCookies(t *testing.T) {
	entries, err := portals(Options{
		Listen: "0.0.0.0:4443", Origin: "https://192.168.1.8:4443", AdminPort: 4444, UserPorts: "4445, 4446",
	})
	if err != nil || len(entries) != 4 {
		t.Fatalf("expected four entries: %#v, %v", entries, err)
	}
	if entries[0].role != "main" || entries[1].role != "admin" || entries[2].role != "user" || entries[3].role != "user" {
		t.Fatalf("unexpected roles: %#v", entries)
	}
	if entries[3].origin != "https://192.168.1.8:4446" || entries[3].listen != "0.0.0.0:4446" {
		t.Fatalf("wrong origin or listen address: %#v", entries[3])
	}
	cookies := make(map[string]bool)
	for _, entry := range entries {
		if !entry.secure || cookies[entry.cookie] {
			t.Fatalf("unexpected cookie configuration: %#v", entry)
		}
		cookies[entry.cookie] = true
	}
}

func TestRejectsConflictingOrUnsafePortals(t *testing.T) {
	base := Options{Listen: "127.0.0.1:44080", Origin: "http://127.0.0.1:44080"}
	for _, ports := range []string{"44080", "44081,44081", "-1", "65536", "a", "44082,"} {
		opts := base
		opts.UserPorts = ports
		if _, err := portals(opts); err == nil {
			t.Errorf("accepted invalid additional ports %q", ports)
		}
	}
	base.Listen = "0.0.0.0:44080"
	if _, err := portals(base); err == nil {
		t.Error("accepted HTTP on a wildcard address")
	}
}
