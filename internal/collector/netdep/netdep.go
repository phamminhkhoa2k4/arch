// Package netdep collects the network dependencies a host takes for
// granted: the DNS resolvers its configuration points at and the cloud
// platform it runs on. It also exposes Promote, which records the
// off-host destinations proxy configurations send traffic to, so those
// dependencies leave the configs and enter the graph. Every fact cites
// the file it came from; anything unreadable becomes a blind spot
// instead of a guess.
package netdep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/collector"
)

// Channel is the evidence channel every fact from this collector is
// written on.
const Channel = "netdep"

// Paths pins the files the collector reads. Empty fields select the
// host defaults; tests point them at fixture copies.
type Paths struct {
	ResolvConf []string // resolv.conf candidates, primary first
	DMIDir     string   // DMI id directory (sys_vendor, product_name)
	DSIdentify string   // cloud-init datasource identification log
}

// Collector reads DNS resolver and cloud platform configuration.
type Collector struct {
	paths Paths
}

// New creates the netdep collector. paths may be nil (host defaults).
func New(paths *Paths) *Collector {
	p := Paths{}
	if paths != nil {
		p = *paths
	}
	if len(p.ResolvConf) == 0 {
		p.ResolvConf = []string{
			"/etc/resolv.conf",
			"/run/systemd/resolve/resolv.conf",
		}
	}
	if p.DMIDir == "" {
		p.DMIDir = "/sys/class/dmi/id"
	}
	if p.DSIdentify == "" {
		p.DSIdentify = "/run/cloud-init/ds-identify.log"
	}
	return &Collector{paths: p}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "netdep" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// Collect writes the resolver inventory first (it never depends on
// the platform) and the platform entity or its blind spot second.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.collectResolvers(sink); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.collectPlatform(sink)
}

// nameserver is one parsed nameserver line of a resolv.conf.
type nameserver struct {
	ip   string
	line int
}

// collectResolvers records every nameserver the host is configured to
// use. The primary resolv.conf is authoritative: the next candidate
// is read only when the primary names no usable upstream (a local
// stub, or no nameserver at all), because in that setup the real
// resolvers live in the systemd-resolved state file.
func (c *Collector) collectResolvers(sink collector.Sink) error {
	primary := c.paths.ResolvConf[0]
	ns, err := readNameservers(primary)
	if err != nil {
		return addResolvBlind(sink, primary, err)
	}
	seen := map[string]bool{}
	if err := writeResolvers(sink, primary, ns, seen); err != nil {
		return err
	}
	if hasUpstream(ns) {
		return nil
	}
	for _, path := range c.paths.ResolvConf[1:] {
		more, err := readNameservers(path)
		if err != nil {
			// The primary pointed here: without this file the
			// upstream resolvers stay invisible.
			return addResolvBlind(sink, path, err)
		}
		if err := writeResolvers(sink, path, more, seen); err != nil {
			return err
		}
		if hasUpstream(more) {
			return nil
		}
	}
	return nil
}

// readNameservers parses one resolv.conf into its nameserver lines.
// A missing or unreadable file is an error: the caller turns it into
// a blind spot rather than reporting an empty resolver set.
func readNameservers(path string) ([]nameserver, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []nameserver
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(f[1])
		if ip == nil {
			continue // not an address: never invent one
		}
		out = append(out, nameserver{ip: ip.String(), line: i + 1})
	}
	return out, nil
}

// hasUpstream reports whether the list names anything beyond a local
// stub resolver.
func hasUpstream(ns []nameserver) bool {
	for _, n := range ns {
		if !isLoopback(n.ip) {
			return true
		}
	}
	return false
}

func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// writeResolvers upserts one dns_resolver entity per nameserver and
// cites the exact line it was read from. seen keeps a resolver listed
// in two files as one entity.
func writeResolvers(sink collector.Sink, file string, list []nameserver, seen map[string]bool) error {
	for _, ns := range list {
		if seen[ns.ip] {
			continue
		}
		seen[ns.ip] = true
		stub := strconv.FormatBool(isLoopback(ns.ip))
		key := "dns_resolver|" + ns.ip
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "dns_resolver",
			Name:        ns.ip,
			IdentityKey: key,
			Fingerprint: fingerprint(key),
			Attributes: map[string]string{
				"nameserver": ns.ip,
				"stub":       stub,
				"file":       file,
				"line":       strconv.Itoa(ns.line),
			},
		}); err != nil {
			return err
		}
		if err := sink.AddEvidence(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          collector.PolarityNeutral,
			Channel:           Channel,
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            fmt.Sprintf("%s:%d", file, ns.line),
			Value: map[string]string{
				"nameserver": ns.ip,
				"stub":       stub,
				"file":       file,
				"line":       strconv.Itoa(ns.line),
			},
		}); err != nil {
			return err
		}
	}
	return nil
}

func addResolvBlind(sink collector.Sink, path string, err error) error {
	return sink.AddBlindSpot(collector.BlindSpot{
		Channel: Channel,
		Reason:  "resolv_conf_unreadable",
		Detail: map[string]string{
			"file":  path,
			"error": err.Error(),
		},
	})
}

// collectPlatform identifies the cloud platform the host runs on.
// DMI is the hardware truth; cloud-init's datasource list is the
// fallback where DMI is not exposed. When neither can be read and no
// platform shows up, the unknown platform is a blind spot: absence of
// DMI is not evidence of absence of a cloud.
func (c *Collector) collectPlatform(sink collector.Sink) error {
	vendor, product, dmiErr := c.readDMI()
	// Best effort: an unreadable datasource log only leaves DMI to
	// decide, and DMI is the stronger signal anyway.
	datasources, dsLine := c.readDatasources()

	provider, source := matchDMI(vendor, product), "dmi"
	if provider == "" {
		if p := matchDatasource(datasources); p != "" {
			provider, source = p, "cloud_init"
		}
	}
	if provider == "" {
		if dmiErr == nil {
			return nil // platform read fine and names no known cloud
		}
		return sink.AddBlindSpot(collector.BlindSpot{
			Channel: Channel,
			Reason:  "dmi_unavailable",
			Detail: map[string]string{
				"file":  c.paths.DMIDir,
				"error": dmiErr.Error(),
			},
		})
	}

	key := "cloud_provider|" + provider
	attrs := map[string]string{
		"provider": provider,
		"source":   source,
	}
	if vendor != "" {
		attrs["sys_vendor"] = vendor
	}
	if product != "" {
		attrs["product_name"] = product
	}
	if len(datasources) > 0 {
		attrs["cloud_init_datasources"] = strings.Join(datasources, " ")
	}
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "cloud_provider",
		Name:        provider,
		IdentityKey: key,
		Fingerprint: fingerprint(key),
		Attributes:  attrs,
	}); err != nil {
		return err
	}
	rawRef := fmt.Sprintf("%s/sys_vendor:1", c.paths.DMIDir)
	if source == "cloud_init" {
		rawRef = fmt.Sprintf("%s:%d", c.paths.DSIdentify, dsLine)
	}
	value := map[string]string{
		"provider": provider,
		"source":   source,
	}
	if vendor != "" {
		value["sys_vendor"] = vendor
	}
	if product != "" {
		value["product_name"] = product
	}
	return sink.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           Channel,
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        nowRFC3339(),
		RawRef:            rawRef,
		Value:             value,
	})
}

// readDMI reads the DMI identity files. Both must be readable: one
// readable file cannot confirm a platform on its own.
func (c *Collector) readDMI() (vendor, product string, err error) {
	v, err := os.ReadFile(filepath.Join(c.paths.DMIDir, "sys_vendor"))
	if err != nil {
		return "", "", err
	}
	p, err := os.ReadFile(filepath.Join(c.paths.DMIDir, "product_name"))
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(v)), strings.TrimSpace(string(p)), nil
}

// readDatasources pulls the datasource candidates cloud-init's
// ds-identify recorded, with the line the list was found on. A
// missing or unreadable log returns nothing: DMI still decides.
func (c *Collector) readDatasources() ([]string, int) {
	data, err := os.ReadFile(c.paths.DSIdentify)
	if err != nil {
		return nil, 0
	}
	for i, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "DSLIST=") {
			continue
		}
		return strings.Fields(strings.TrimPrefix(line, "DSLIST=")), i + 1
	}
	return nil, 0
}

// cloudPlatforms maps DMI identity onto the platform id used in the
// inventory. Where a product is named both must match: "Microsoft
// Corporation" alone is a Surface laptop, not an Azure virtual
// machine. Vendors that only mean on-premises hardware (VMware,
// QEMU, Dell) deliberately match nothing.
var cloudPlatforms = []struct {
	provider string
	vendor   string
	product  string
}{
	{provider: "aws", vendor: "amazon"},
	{provider: "gcp", vendor: "google", product: "compute engine"},
	{provider: "azure", vendor: "microsoft", product: "virtual machine"},
	{provider: "digitalocean", vendor: "digitalocean"},
	{provider: "alibaba", vendor: "alibaba"},
	{provider: "alibaba", vendor: "alicloud"},
	{provider: "openstack", vendor: "openstack"},
	{provider: "oracle", vendor: "oraclecloud"},
}

// matchDMI returns the platform the DMI identity names, or "" when
// it names no known cloud.
func matchDMI(vendor, product string) string {
	v := strings.ToLower(vendor)
	p := strings.ToLower(product)
	for _, c := range cloudPlatforms {
		if !strings.Contains(v, c.vendor) {
			continue
		}
		if c.product != "" && !strings.Contains(p, c.product) {
			continue
		}
		return c.provider
	}
	return ""
}

// cloudDatasources maps cloud-init datasource names onto the same
// platform ids. Non-cloud datasources (NoCloud, config drive, WSL)
// deliberately map to nothing.
var cloudDatasources = map[string]string{
	"ec2":          "aws",
	"gce":          "gcp",
	"azure":        "azure",
	"digitalocean": "digitalocean",
	"aliyun":       "alibaba",
	"openstack":    "openstack",
	"oracle":       "oracle",
}

// matchDatasource returns the platform a cloud-init datasource list
// names, or "" when it names no known cloud.
func matchDatasource(list []string) string {
	for _, ds := range list {
		if p, ok := cloudDatasources[strings.ToLower(ds)]; ok {
			return p
		}
	}
	return ""
}

// fingerprint hashes the stable identity so a rescan of the same
// dependency reports the same fingerprint.
func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// compile-time interface check
var _ collector.Collector = (*Collector)(nil)
