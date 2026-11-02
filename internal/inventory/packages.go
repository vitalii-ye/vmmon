package inventory

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	scalibrlog "github.com/google/osv-scalibr/log"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

// Scalibr's default logger writes unstructured lines to stderr. Route it through
// slog so it follows the --verbose level and output format.
func init() { scalibrlog.SetLogger(scalibrLogger{}) }

// readPackages returns the installed packages sorted by name, then arch.
func readPackages(ctx context.Context, root *os.Root, distro string) ([]Package, error) {
	data, err := root.ReadFile(statusFile)
	if err != nil {
		return nil, fmt.Errorf("read dpkg status: %w", err)
	}
	extractor, err := dpkg.New(&cpb.PluginConfig{})
	if err != nil {
		return nil, fmt.Errorf("dpkg extractor: %w", err)
	}
	found, err := extractor.Extract(ctx, &filesystem.ScanInput{
		FS:     root.FS().(scalibrfs.FS),
		Path:   statusFile,
		Reader: bytes.NewReader(data),
	})
	if err != nil {
		return nil, fmt.Errorf("parse dpkg status: %w", err)
	}
	if len(found.Packages) == 0 {
		return nil, fmt.Errorf("parse dpkg status: no installed packages in %s", statusFile)
	}

	pkgs := make([]Package, 0, len(found.Packages))
	for _, p := range found.Packages {
		m, ok := p.Metadata.(*dpkgmeta.Metadata)
		if !ok {
			return nil, fmt.Errorf("parse dpkg status: %s: unexpected metadata %T", p.Name, p.Metadata)
		}
		pkgs = append(pkgs, newPackage(distro, p.Name, p.Version, m.Architecture, m.SourceName, m.SourceVersion))
	}
	slices.SortFunc(pkgs, func(a, b Package) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Arch, b.Arch))
	})
	return pkgs, nil
}

// newPackage resolves a binary package's source identity from its dpkg fields.
//
// Only versioned kernel images are normalised: their code really is built from
// the unsigned source, whose records and versions OSV uses. Debian's metapackage
// linux-image-amd64 also comes from linux-signed-amd64, but it holds no kernel
// and may be ahead of what is installed or running, so it keeps its literal
// source. OSV has no records for linux-signed* or linux-meta*, so metapackages
// can never produce a kernel finding.
func newPackage(distro, name, version, arch, sourceName, sourceVersion string) Package {
	p := Package{
		Name:          name,
		Version:       version,
		Arch:          arch,
		SourceName:    cmp.Or(sourceName, name),
		SourceVersion: cmp.Or(sourceVersion, version),
		IsKernelImage: kernelRelease(name) != "",
	}
	if p.IsKernelImage {
		if unsigned, ok := unsignedSource(distro, p.SourceName); ok {
			// A signed source has its own version (6.1.112+1 for 6.1.112-1), but
			// the image's binary version is that of the unsigned source.
			p.SourceName, p.SourceVersion = unsigned, version
		}
	}
	return p
}

// unsignedSource maps a linux-signed* source to the source it signs. Debian
// suffixes the architecture: linux-signed-amd64 -> linux and
// linux-signed-6.12-amd64 -> linux-6.12. Ubuntu keeps the flavour:
// linux-signed -> linux and linux-signed-hwe-6.8 -> linux-hwe-6.8.
func unsignedSource(distro, source string) (string, bool) {
	flavour, ok := strings.CutPrefix(source, "linux-signed")
	if !ok || (flavour != "" && flavour[0] != '-') {
		return "", false
	}
	if i := strings.LastIndexByte(flavour, '-'); distro == "debian" && i >= 0 {
		flavour = flavour[:i]
	}
	return "linux" + flavour, true
}

// scalibrLogger adapts scalibr's logger to slog.
type scalibrLogger struct{}

func (scalibrLogger) Errorf(format string, args ...any) { scalibrWarn(fmt.Sprintf(format, args...)) }
func (scalibrLogger) Error(args ...any)                 { scalibrWarn(fmt.Sprint(args...)) }
func (scalibrLogger) Warnf(format string, args ...any)  { scalibrWarn(fmt.Sprintf(format, args...)) }
func (scalibrLogger) Warn(args ...any)                  { scalibrWarn(fmt.Sprint(args...)) }
func (scalibrLogger) Infof(format string, args ...any)  { scalibrDebug(fmt.Sprintf(format, args...)) }
func (scalibrLogger) Info(args ...any)                  { scalibrDebug(fmt.Sprint(args...)) }
func (scalibrLogger) Debugf(format string, args ...any) { scalibrDebug(fmt.Sprintf(format, args...)) }
func (scalibrLogger) Debug(args ...any)                 { scalibrDebug(fmt.Sprint(args...)) }

func scalibrWarn(msg string)  { slog.Warn(msg, "component", "scalibr") }
func scalibrDebug(msg string) { slog.Debug(msg, "component", "scalibr") }
