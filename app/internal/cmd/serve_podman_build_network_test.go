package cmd

import (
	"net/http"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

func TestServeChainPodmanCompatBuildRequiresPrivateNetwork(t *testing.T) {
	daemon := newImageBuildChainDaemon()
	daemon.shortNameAliases = map[string]string{}
	daemon.enforceDockerHubOff = true
	addr := newImageNameChain(t, daemon, func(cfg *config.Config) { cfg.Ownership.Owner = ""; cfg.RequestBody.Build.AllowHostNetwork = false })
	runImageNameChainStep(t, addr, daemon, imageBuildChainStep("default host network refused", "/build?t=mine%2Fnew%3Av2", "", "", http.StatusForbidden))
	if daemon.nameTarget("localhost/mine/new:v2") != "" {
		t.Fatal("denied build changed the image store")
	}
	runImageNameChainStep(t, addr, daemon, imageBuildChainStep("private network admitted", "/build?t=mine%2Fnew%3Av2&nsoptions=%5B%7B%22Name%22%3A%22network%22%7D%5D", "localhost/mine/new:v2", "", http.StatusOK))
}
