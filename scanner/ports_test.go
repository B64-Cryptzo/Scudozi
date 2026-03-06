package scanner

import "testing"

func TestClassifyAddressScopes(t *testing.T) {
	idx := interfaceIndex{
		byAddress: map[string]string{
			"127.0.0.1":   "loopback",
			"192.168.1.8": "lan",
			"172.23.64.1": "virtual",
			"8.8.8.8":     "public",
		},
	}

	cases := []struct {
		host         string
		wantScope    string
		wantReach    string
		wantIfaceTyp string
	}{
		{"127.0.0.1", BindScopeLocalhostOnly, ReachabilityLocalOnly, "loopback"},
		{"0.0.0.0", BindScopeAllInterfaces, ReachabilityPotentialExternal, "all_interfaces"},
		{"192.168.1.8", BindScopeLANOnly, ReachabilityLANReachable, "lan"},
		{"172.23.64.1", BindScopeVirtualOnly, ReachabilityUnknown, "virtual"},
		{"8.8.8.8", BindScopePublicIPBound, ReachabilityPublicInterface, "public"},
	}

	for _, tc := range cases {
		scope, reach, iface := classifyAddress(tc.host, idx)
		if scope != tc.wantScope || reach != tc.wantReach || iface != tc.wantIfaceTyp {
			t.Fatalf("classifyAddress(%q) = (%q,%q,%q), want (%q,%q,%q)",
				tc.host, scope, reach, iface, tc.wantScope, tc.wantReach, tc.wantIfaceTyp)
		}
	}
}
