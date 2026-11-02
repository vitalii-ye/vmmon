// Package inventory describes what is installed on a host.
package inventory

// Release identifies a supported distro release.
type Release struct {
	// Distro is the os-release ID: "debian" or "ubuntu".
	Distro string `json:"distro"`
	// Version is the os-release VERSION_ID: "12", "24.04".
	Version  string `json:"version"`
	Codename string `json:"codename,omitempty"`
	// Ecosystem is the exact OSV ecosystem: "Debian:12", "Ubuntu:24.04:LTS".
	Ecosystem string `json:"ecosystem"`
	// Root is the OSV bucket directory: "Debian", "Ubuntu".
	Root string `json:"root"`
}

// Package is one installed binary package with its source identity.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	// SourceName and SourceVersion are what OSV matching uses. They are always
	// populated: a package with no Source field has source = binary, and a
	// Source field without a parenthesised version uses the binary version.
	SourceName    string `json:"source_name"`
	SourceVersion string `json:"source_version"`
	// IsKernelImage marks linux-image-* packages. Their source identity is
	// normalised from linux-signed* to the unsigned source OSV records use.
	IsKernelImage bool `json:"is_kernel_image,omitempty"`
}

// Kernel describes the kernel state.
type Kernel struct {
	// Release is `uname -r`, empty when scanning an offline root.
	Release string `json:"release,omitempty"`
	// SourceName and Version identify the running kernel in OSV terms, found
	// through its linux-image-<release> package. They fall back to the newest
	// installed image when scanning an offline root, and are empty when no
	// image is installed (containers).
	SourceName string `json:"source_name,omitempty"`
	Version    string `json:"version,omitempty"`
	// RebootRequired is true when /var/run/reboot-required exists or a newer
	// kernel image than the running one is installed.
	RebootRequired bool `json:"reboot_required"`
	// RebootPackages comes from /var/run/reboot-required.pkgs.
	RebootPackages []string `json:"reboot_packages,omitempty"`
}

// Host is the complete inventory.
type Host struct {
	Hostname string    `json:"hostname"`
	Release  Release   `json:"release"`
	Kernel   Kernel    `json:"kernel"`
	Packages []Package `json:"packages"`
}
