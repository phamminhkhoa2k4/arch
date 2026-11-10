// Package traefik parses Traefik configuration into the small subset
// the scanner needs: the file provider location from the static
// config, then the routers and services the dynamic files declare.
// It reads files only and never executes anything from the config.
package traefik

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v4"
)

// DefaultRoot is the standard Traefik static entry point.
const DefaultRoot = "/etc/traefik/traefik.yml"

// AltRoots are additional standard static locations tried when the
// default path does not exist.
var AltRoots = []string{"/etc/traefik/traefik.yaml"}

// TOMLRoots are locations of the TOML flavour of the static config.
// They are detect-only: without a TOML library the collector reports
// a blind spot instead of reading them.
var TOMLRoots = []string{"/etc/traefik/traefik.toml"}

// FileError is one configuration problem at a known position.
type FileError struct {
	File string
	Line int
	Err  error
}

func (e FileError) Error() string { return fmt.Sprintf("%s:%d: %v", e.File, e.Line, e.Err) }

// Config is the extracted static graph of one Traefik installation.
type Config struct {
	Routers  []Router
	Services []Service
	// Errors are parse problems: the file that failed contributes no
	// inventory, every other file still does.
	Errors []FileError
	// Unreadable lists dynamic files and directories that could not
	// be read (missing path or denied permission).
	Unreadable []FileError
	// Unsupported lists dynamic files written in a format the
	// scanner does not parse (TOML).
	Unsupported []FileError
	// Providers names the non-file providers the static config
	// declares (docker, kubernetes, ...): their routing is not
	// inventoried from files.
	Providers []string
}

// Router is one http or tcp router section.
type Router struct {
	Protocol    string // "http" or "tcp"
	Name        string
	File        string
	Line        int // best-effort line of the router's name key
	Rule        string
	Service     string
	EntryPoints []string
	Middlewares []string
}

// Key is the stable identity of the router: names are unique per
// protocol section within one provider.
func (r *Router) Key() string {
	return "traefik_router|" + r.Protocol + "#" + r.Name
}

// RawRef cites the file and line of the router for evidence.
func (r *Router) RawRef() string { return rawRef(r.File, r.Line) }

// Fingerprint hashes the static shape so a changed rule shows up as
// a changed fingerprint.
func (r *Router) Fingerprint() string {
	return fingerprintOf(
		r.Protocol, r.Name, r.Rule, r.Service,
		strings.Join(r.EntryPoints, ","), strings.Join(r.Middlewares, ","),
	)
}

// Service is one http or tcp service section: its servers when it
// load-balances, its target service names when it splits traffic.
type Service struct {
	Protocol string // "http" or "tcp"
	Name     string
	File     string
	Line     int
	Kind     string   // "loadBalancer", "weighted" or "mirroring"
	Servers  []Server // loadBalancer targets
	Refs     []string // weighted/mirroring target service names
}

// Server is one declared target of a load-balancing service.
type Server struct {
	Target string // URL for http services, address for tcp services
}

// Key is the stable identity of the service: names are unique per
// protocol section within one provider.
func (s *Service) Key() string {
	return "traefik_service|" + s.Protocol + "#" + s.Name
}

// RawRef cites the file and line of the service for evidence.
func (s *Service) RawRef() string { return rawRef(s.File, s.Line) }

// Fingerprint hashes the static shape so a changed server list shows
// up as a changed fingerprint.
func (s *Service) Fingerprint() string {
	parts := []string{s.Protocol, s.Name, s.Kind}
	for _, sv := range s.Servers {
		parts = append(parts, sv.Target)
	}
	parts = append(parts, strings.Join(s.Refs, ","))
	return fingerprintOf(parts...)
}

// rawRef renders file:line, or just the file when no line could be
// located.
func rawRef(file string, line int) string {
	if line <= 0 {
		return file
	}
	return file + ":" + strconv.Itoa(line)
}

// fingerprintOf hashes the rendered shape into a fingerprint string.
func fingerprintOf(parts ...string) string {
	return sha256Hex(strings.Join(parts, "\x00"))
}

// staticFile is the part of the static config the scanner reads:
// which providers are declared and where the file provider looks.
type staticFile struct {
	Providers map[string]any `yaml:"providers"`
}

// Load reads the static config and every dynamic file it points at.
// A static read failure propagates so the collector can report it as
// a blind spot; problems inside the files are recorded on cfg.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}

	var st staticFile
	if err := yaml.Unmarshal(data, &st); err != nil {
		cfg.Errors = append(cfg.Errors, FileError{File: path, Line: yamlLine(err), Err: err})
		return cfg, nil // no provider map: the dynamic location is unknown
	}

	for name := range st.Providers {
		if name != "file" {
			cfg.Providers = append(cfg.Providers, name)
		}
	}
	sort.Strings(cfg.Providers)

	dir, file := fileProviderPaths(st.Providers)
	if file != "" {
		cfg.loadDynamic(file)
	}
	if dir != "" {
		cfg.loadDir(dir)
	}
	return cfg, nil
}

// fileProviderPaths extracts the file provider's single filename and
// its directory watch path.
func fileProviderPaths(providers map[string]any) (dir, file string) {
	fm, ok := asStringMap(providers["file"])
	if !ok {
		return "", ""
	}
	return fm["directory"], fm["filename"]
}

// loadDir reads every YAML file directly inside a file-provider
// directory. TOML files are recorded as unsupported; other
// extensions are left alone.
func (cfg *Config) loadDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		cfg.Unreadable = append(cfg.Unreadable, FileError{File: dir, Err: err})
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		switch strings.ToLower(filepath.Ext(name)) {
		case ".yml", ".yaml":
			cfg.loadDynamic(path)
		case ".toml":
			cfg.Unsupported = append(cfg.Unsupported, FileError{
				File: path, Err: fmt.Errorf("TOML dynamic config is not parsed"),
			})
		}
	}
}

// loadDynamic reads and parses one dynamic config file.
func (cfg *Config) loadDynamic(path string) {
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		cfg.Unsupported = append(cfg.Unsupported, FileError{
			File: path, Err: fmt.Errorf("TOML dynamic config is not parsed"),
		})
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		cfg.Unreadable = append(cfg.Unreadable, FileError{File: path, Err: err})
		return
	}
	var dyn dynamicFile
	if err := yaml.Unmarshal(data, &dyn); err != nil {
		cfg.Errors = append(cfg.Errors, FileError{File: path, Line: yamlLine(err), Err: err})
		return
	}
	src := string(data)
	cfg.collectRouters(path, src, dyn.HTTP, dyn.TCP)
	cfg.collectServices(path, src, dyn.HTTP, dyn.TCP)
}

// dynamicFile is the routing part of a dynamic config file.
type dynamicFile struct {
	HTTP *httpSection `yaml:"http"`
	TCP  *tcpSection  `yaml:"tcp"`
}

type httpSection struct {
	Routers  map[string]httpRouter  `yaml:"routers"`
	Services map[string]httpService `yaml:"services"`
}

type httpRouter struct {
	Rule        string   `yaml:"rule"`
	Service     string   `yaml:"service"`
	EntryPoints []string `yaml:"entryPoints"`
	Middlewares []string `yaml:"middlewares"`
}

type httpService struct {
	LoadBalancer *struct {
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
	} `yaml:"loadBalancer"`
	Weighted *struct {
		Services []struct {
			Name string `yaml:"name"`
		} `yaml:"services"`
	} `yaml:"weighted"`
	Mirroring *struct {
		Services []struct {
			Name string `yaml:"name"`
		} `yaml:"services"`
	} `yaml:"mirroring"`
}

type tcpSection struct {
	Routers  map[string]tcpRouter  `yaml:"routers"`
	Services map[string]tcpService `yaml:"services"`
}

type tcpRouter struct {
	Service     string   `yaml:"service"`
	EntryPoints []string `yaml:"entryPoints"`
}

type tcpService struct {
	LoadBalancer *struct {
		Servers []struct {
			Address string `yaml:"address"`
		} `yaml:"servers"`
	} `yaml:"loadBalancer"`
}

// collectRouters records every http and tcp router of one file.
func (cfg *Config) collectRouters(file, src string, httpSec *httpSection, tcpSec *tcpSection) {
	if httpSec != nil {
		for _, name := range sortedKeys(httpSec.Routers) {
			r := httpSec.Routers[name]
			cfg.Routers = append(cfg.Routers, Router{
				Protocol: "http", Name: name, File: file,
				Line:        findLine(src, name),
				Rule:        r.Rule,
				Service:     r.Service,
				EntryPoints: r.EntryPoints,
				Middlewares: r.Middlewares,
			})
		}
	}
	if tcpSec != nil {
		for _, name := range sortedKeys(tcpSec.Routers) {
			r := tcpSec.Routers[name]
			cfg.Routers = append(cfg.Routers, Router{
				Protocol: "tcp", Name: name, File: file,
				Line:        findLine(src, name),
				Service:     r.Service,
				EntryPoints: r.EntryPoints,
			})
		}
	}
}

// collectServices records every http and tcp service of one file.
func (cfg *Config) collectServices(file, src string, httpSec *httpSection, tcpSec *tcpSection) {
	if httpSec != nil {
		for _, name := range sortedKeys(httpSec.Services) {
			s := httpSec.Services[name]
			svc := Service{Protocol: "http", Name: name, File: file, Line: findLine(src, name)}
			switch {
			case s.LoadBalancer != nil:
				svc.Kind = "loadBalancer"
				for _, srv := range s.LoadBalancer.Servers {
					svc.Servers = append(svc.Servers, Server{Target: srv.URL})
				}
			case s.Weighted != nil:
				svc.Kind = "weighted"
				for _, ref := range s.Weighted.Services {
					svc.Refs = append(svc.Refs, ref.Name)
				}
			case s.Mirroring != nil:
				svc.Kind = "mirroring"
				for _, ref := range s.Mirroring.Services {
					svc.Refs = append(svc.Refs, ref.Name)
				}
			default:
				svc.Kind = "loadBalancer" // declared but empty: no targets
			}
			cfg.Services = append(cfg.Services, svc)
		}
	}
	if tcpSec != nil {
		for _, name := range sortedKeys(tcpSec.Services) {
			s := tcpSec.Services[name]
			svc := Service{Protocol: "tcp", Name: name, File: file, Line: findLine(src, name), Kind: "loadBalancer"}
			if s.LoadBalancer != nil {
				for _, srv := range s.LoadBalancer.Servers {
					svc.Servers = append(svc.Servers, Server{Target: srv.Address})
				}
			}
			cfg.Services = append(cfg.Services, svc)
		}
	}
}

// sortedKeys returns a map's keys in sorted order so the inventory
// is deterministic across runs.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// findLine locates the line of a YAML key by name, best effort: the
// first mapping key that equals the name wins, 0 when none does.
func findLine(src, name string) int {
	for i, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		key, _, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `"'`)
		if key == name {
			return i + 1
		}
	}
	return 0
}

// yamlLine extracts the line number from a YAML error when it has
// one; 0 otherwise.
func yamlLine(err error) int {
	msg := err.Error()
	const prefix = "yaml: line "
	if !strings.HasPrefix(msg, prefix) {
		return 0
	}
	rest := msg[len(prefix):]
	digit, _, _ := strings.Cut(rest, ":")
	n, convErr := strconv.Atoi(strings.TrimSpace(digit))
	if convErr != nil {
		return 0
	}
	return n
}

// asStringMap narrows a decoded YAML value to a string map.
func asStringMap(v any) (map[string]string, bool) {
	switch m := v.(type) {
	case map[string]any:
		out := make(map[string]string, len(m))
		for k, val := range m {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
		return out, true
	case map[any]any:
		out := make(map[string]string, len(m))
		for k, val := range m {
			ks, ok := k.(string)
			if !ok {
				continue
			}
			if s, ok := val.(string); ok {
				out[ks] = s
			}
		}
		return out, true
	}
	return nil, false
}
