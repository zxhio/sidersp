package rule

import "testing"

func TestActionName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		code   uint16
		want   string
		wantOK bool
	}{
		{name: "tcp reset", code: ActionTCPReset, want: "tcp_reset", wantOK: true},
		{name: "dns sinkhole", code: ActionDNSSinkhole, want: "dns_sinkhole", wantOK: true},
		{name: "unknown", code: 99},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := ActionName(tc.code)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("ActionName(%d) = %q,%v, want %q,%v", tc.code, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestNormalizeActionName(t *testing.T) {
	t.Parallel()

	got, ok := NormalizeActionName(" TCP_RESET ")
	if got != "tcp_reset" || !ok {
		t.Fatalf("NormalizeActionName() = %q,%v, want %q,true", got, ok, "tcp_reset")
	}

	if got, ok := NormalizeActionName("drop"); got != "" || ok {
		t.Fatalf("NormalizeActionName(drop) = %q,%v, want empty,false", got, ok)
	}
}

func TestUserSpaceResponseActionName(t *testing.T) {
	t.Parallel()

	if got, ok := UserSpaceResponseActionName(ActionDNSRefused); got != "dns_refused" || !ok {
		t.Fatalf("UserSpaceResponseActionName() = %q,%v, want %q,true", got, ok, "dns_refused")
	}
	if got, ok := UserSpaceResponseActionName(ActionTCPReset); got != "" || ok {
		t.Fatalf("UserSpaceResponseActionName(tcp_reset) = %q,%v, want empty,false", got, ok)
	}
	if !IsUserSpaceResponseActionName("dns_sinkhole") {
		t.Fatal("IsUserSpaceResponseActionName(dns_sinkhole) = false, want true")
	}
	if IsUserSpaceResponseActionName("tcp_reset") {
		t.Fatal("IsUserSpaceResponseActionName(tcp_reset) = true, want false")
	}
}
