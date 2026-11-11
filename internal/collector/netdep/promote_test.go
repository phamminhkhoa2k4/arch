package netdep

import (
	"testing"

	"archaeologist/internal/collector"
)

func TestExternalKey(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"cdn.example.test", 0, "external_host|cdn.example.test"},
		{"cdn.example.test", 443, "external_host|cdn.example.test:443"},
		{"192.0.2.10", 9443, "external_host|192.0.2.10:9443"},
		{"[2001:db8::1]", 8443, "external_host|[2001:db8::1]:8443"},
		{"[2001:db8::1]", 0, "external_host|2001:db8::1"},
	}
	for _, tc := range cases {
		if got := ExternalKey(tc.host, tc.port); got != tc.want {
			t.Errorf("ExternalKey(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

// seedReferrer registers a referring route plus the evidence ref its
// edge must point at, mirroring what the proxy collectors emit first.
func seedReferrer(t *testing.T, s *recSink, key, ref string) {
	t.Helper()
	if err := s.UpsertEntity(collector.Entity{
		Kind: "nginx_route", Name: key, IdentityKey: key,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "nginx",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        nowRFC3339(),
		RawRef:            "/etc/nginx/nginx.conf:10",
		Ref:               ref,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPromoteLinksOffHostTarget(t *testing.T) {
	sink := newRecSink()
	ref := "nginx-route:nginx_route|/ext/"
	seedReferrer(t, sink, "nginx_route|/ext/", ref)

	err := Promote(sink, Link{
		FromKey:  "nginx_route|/ext/",
		Ref:      ref,
		Channel:  "nginx",
		Strength: collector.StrengthDeterministic,
		RawRef:   "/etc/nginx/nginx.conf:42",
		Target: Target{
			Host:   "example.test",
			Scheme: "https",
			Raw:    "https://example.test/",
		},
	})
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}

	ent, ok := sink.entities["external_host|example.test"]
	if !ok {
		t.Fatalf("entities = %v, want external_host|example.test", keys(sink))
	}
	if ent.Kind != ExternalKind || ent.Name != "example.test" {
		t.Errorf("entity = %+v, want external_host named example.test", ent)
	}
	if ent.Attributes["host"] != "example.test" || ent.Attributes["scheme"] != "https" {
		t.Errorf("attrs = %v, want host and scheme", ent.Attributes)
	}

	ev := evidenceFor(t, sink, "external_host|example.test")
	if ev.Channel != "nginx" || ev.RawRef != "/etc/nginx/nginx.conf:42" {
		t.Errorf("evidence = %+v, want nginx channel citing the config line", ev)
	}
	if ev.Value["target"] != "https://example.test/" {
		t.Errorf("value target = %q, want the address as written", ev.Value["target"])
	}

	if len(sink.edges) != 1 {
		t.Fatalf("edges = %+v, want one", sink.edges)
	}
	e := sink.edges[0]
	if e.Kind != "proxies_to" || e.SrcIdentityKey != "nginx_route|/ext/" ||
		e.DstIdentityKey != "external_host|example.test" || e.EvidenceRef != ref {
		t.Errorf("edge = %+v, want proxies_to from the route to the destination", e)
	}
}

func TestPromoteSharesOneEntityPerDestination(t *testing.T) {
	sink := newRecSink()
	refA := "nginx-route:nginx_route|/a/"
	refB := "caddy-route:caddy_route|/b/"
	seedReferrer(t, sink, "nginx_route|/a/", refA)
	seedReferrer(t, sink, "caddy_route|/b/", refB)

	if err := Promote(sink, Link{
		FromKey: "nginx_route|/a/", Ref: refA, Channel: "nginx",
		Strength: collector.StrengthDeterministic,
		RawRef:   "/etc/nginx/nginx.conf:12",
		Target:   Target{Host: "api.example.test", Port: 8443, Raw: "api.example.test:8443"},
	}); err != nil {
		t.Fatalf("Promote nginx: %v", err)
	}
	if err := Promote(sink, Link{
		FromKey: "caddy_route|/b/", Ref: refB, Channel: "caddy",
		Strength: collector.StrengthDeterministic,
		RawRef:   "/etc/caddy/Caddyfile:4",
		Target:   Target{Host: "api.example.test", Port: 8443, Scheme: "http", Raw: "api.example.test:8443"},
	}); err != nil {
		t.Fatalf("Promote caddy: %v", err)
	}

	if countKind(sink, ExternalKind) != 1 {
		t.Fatalf("external_host count = %d, want 1 shared entity", countKind(sink, ExternalKind))
	}
	externalEvidence := 0
	for _, ev := range sink.evidence {
		if ev.EntityIdentityKey == "external_host|api.example.test:8443" {
			externalEvidence++
		}
	}
	if externalEvidence != 2 {
		t.Errorf("external evidence = %d, want one row per referring config", externalEvidence)
	}
	if len(sink.edges) != 2 {
		t.Errorf("edges = %d, want both referrers linked", len(sink.edges))
	}
}

func TestPromoteIgnoresHostlessTarget(t *testing.T) {
	sink := newRecSink()
	if err := Promote(sink, Link{
		FromKey: "nginx_route|/x/", Ref: "nginx-route:nginx_route|/x/",
		Channel: "nginx", Strength: collector.StrengthDeterministic,
		RawRef: "/etc/nginx/nginx.conf:9",
		Target: Target{Raw: "$BACKEND"},
	}); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if len(sink.entities) != 0 || len(sink.evidence) != 0 || len(sink.edges) != 0 {
		t.Errorf("hostless target produced output: %+v", sink)
	}
}
