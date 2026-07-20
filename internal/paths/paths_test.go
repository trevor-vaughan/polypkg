package paths

import (
	"os"
	"path/filepath"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("UserDataHome", func() {
	It("on Linux uses XDG_DATA_HOME when set to an absolute path", func() {
		if runtime.GOOS != "linux" {
			Skip("Linux-specific path test")
		}
		GinkgoT().Setenv("XDG_DATA_HOME", "/custom/data")
		got, err := UserDataHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("/custom/data/polypkg"))
	})

	It("on Linux defaults to ~/.local/share/polypkg when XDG_DATA_HOME is unset", func() {
		if runtime.GOOS != "linux" {
			Skip("Linux-specific path test")
		}
		GinkgoT().Setenv("XDG_DATA_HOME", "")
		home, err := os.UserHomeDir()
		Expect(err).NotTo(HaveOccurred())
		got, err := UserDataHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(filepath.Join(home, ".local/share/polypkg")))
	})

	It("on Linux ignores a relative XDG_DATA_HOME and falls back to the default", func() {
		if runtime.GOOS != "linux" {
			Skip("Linux-specific path test")
		}
		GinkgoT().Setenv("XDG_DATA_HOME", "relative/data")
		home, err := os.UserHomeDir()
		Expect(err).NotTo(HaveOccurred())
		got, err := UserDataHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(filepath.Join(home, ".local", "share", "polypkg")))
	})
})

var _ = Describe("UserStateHome", func() {
	It("on Linux defaults to ~/.local/state/polypkg when XDG_STATE_HOME is unset", func() {
		if runtime.GOOS != "linux" {
			Skip("Linux-specific path test")
		}
		GinkgoT().Setenv("XDG_STATE_HOME", "")
		home, err := os.UserHomeDir()
		Expect(err).NotTo(HaveOccurred())
		got, err := UserStateHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(filepath.Join(home, ".local/state/polypkg")))
	})

	It("on Linux ignores a relative XDG_STATE_HOME and falls back to the default", func() {
		if runtime.GOOS != "linux" {
			Skip("Linux-specific path test")
		}
		GinkgoT().Setenv("XDG_STATE_HOME", "relative/state")
		home, err := os.UserHomeDir()
		Expect(err).NotTo(HaveOccurred())
		got, err := UserStateHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(filepath.Join(home, ".local", "state", "polypkg")))
	})

	It("uses XDG_STATE_HOME when set to an absolute path", func() {
		GinkgoT().Setenv("XDG_STATE_HOME", "/custom/state")
		got, err := UserStateHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("/custom/state/polypkg"))
	})
})

var _ = Describe("UserConfigHome", func() {
	It("on Linux defaults to ~/.config/polypkg when XDG_CONFIG_HOME is unset", func() {
		if runtime.GOOS != "linux" {
			Skip("Linux-specific path test")
		}
		GinkgoT().Setenv("XDG_CONFIG_HOME", "")
		home, err := os.UserHomeDir()
		Expect(err).NotTo(HaveOccurred())
		got, err := UserConfigHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(filepath.Join(home, ".config/polypkg")))
	})

	It("on Linux ignores a relative XDG_CONFIG_HOME and falls back to the default", func() {
		if runtime.GOOS != "linux" {
			Skip("Linux-specific path test")
		}
		GinkgoT().Setenv("XDG_CONFIG_HOME", "relative/config")
		home, err := os.UserHomeDir()
		Expect(err).NotTo(HaveOccurred())
		got, err := UserConfigHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(filepath.Join(home, ".config", "polypkg")))
	})

	It("uses XDG_CONFIG_HOME when set to an absolute path", func() {
		GinkgoT().Setenv("XDG_CONFIG_HOME", "/custom/config")
		got, err := UserConfigHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("/custom/config/polypkg"))
	})
})

var _ = Describe("UserBinHome", func() {
	It("honors an absolute XDG_BIN_HOME", func() {
		GinkgoT().Setenv("XDG_BIN_HOME", "/custom/bin")
		dir, err := UserBinHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(dir).To(Equal("/custom/bin"))
	})

	It("ignores a relative XDG_BIN_HOME and falls back to ~/.local/bin", func() {
		GinkgoT().Setenv("XDG_BIN_HOME", "relative/bin")
		GinkgoT().Setenv("HOME", "/home/tester")
		dir, err := UserBinHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(dir).To(Equal("/home/tester/.local/bin"))
	})

	It("defaults to ~/.local/bin when XDG_BIN_HOME is unset", func() {
		GinkgoT().Setenv("XDG_BIN_HOME", "")
		GinkgoT().Setenv("HOME", "/home/tester")
		dir, err := UserBinHome()
		Expect(err).NotTo(HaveOccurred())
		Expect(dir).To(Equal("/home/tester/.local/bin"))
	})
})

var _ = Describe("user completion dirs", func() {
	It("derives bash/zsh from XDG_DATA_HOME and fish from XDG_CONFIG_HOME", func() {
		GinkgoT().Setenv("XDG_DATA_HOME", "/d")
		GinkgoT().Setenv("XDG_CONFIG_HOME", "/c")
		bash, err := UserBashCompletionDir()
		Expect(err).NotTo(HaveOccurred())
		Expect(bash).To(Equal("/d/bash-completion/completions"))
		zsh, err := UserZshCompletionDir()
		Expect(err).NotTo(HaveOccurred())
		Expect(zsh).To(Equal("/d/zsh/site-functions"))
		fish, err := UserFishCompletionDir()
		Expect(err).NotTo(HaveOccurred())
		Expect(fish).To(Equal("/c/fish/completions"))
	})
})

var _ = Describe("user applications dir", func() {
	It("derives applications from XDG_DATA_HOME", func() {
		GinkgoT().Setenv("XDG_DATA_HOME", "/d")
		got, err := UserApplicationsDir()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("/d/applications"))
	})
})

var _ = Describe("user mime packages dir", func() {
	It("derives mime/packages from XDG_DATA_HOME", func() {
		GinkgoT().Setenv("XDG_DATA_HOME", "/d")
		got, err := UserMimePackagesDir()
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("/d/mime/packages"))
	})
})

var _ = Describe("System directories", func() {
	It("SystemDataDir returns /var/lib/polypkg", func() {
		Expect(SystemDataDir()).To(Equal("/var/lib/polypkg"))
	})

	It("SystemConfigDir returns /etc/polypkg", func() {
		Expect(SystemConfigDir()).To(Equal("/etc/polypkg"))
	})

	It("SystemStateDir returns /var/lib/polypkg", func() {
		Expect(SystemStateDir()).To(Equal("/var/lib/polypkg"))
	})
})
