package ownership

import (
	"net/http"
	"testing"
)

type identifierClassifier func(method, path string) (string, bool)

type identifierCollectionRoute struct {
	name               string
	method             string
	path               string
	resourceMethod     string
	resourcePath       string
	resourceIdentifier string
}

func testIdentifierCollectionRoutes(t *testing.T, classify identifierClassifier, routes []identifierCollectionRoute) {
	t.Helper()
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()
			if identifier, ok := classify(route.method, route.path); ok {
				t.Errorf("classify(%q, %q) = %q, true; collection route must not be a resource identifier", route.method, route.path, identifier)
			}

			if route.resourcePath == "" {
				return
			}
			identifier, ok := classify(route.resourceMethod, route.resourcePath)
			if !ok || identifier != route.resourceIdentifier {
				t.Errorf("classify(%q, %q) = %q, %v; want %q, true for keyword-named resource", route.resourceMethod, route.resourcePath, identifier, ok, route.resourceIdentifier)
			}
		})
	}
}

func TestDockerCollectionRoutesAreNotResourceIdentifiers(t *testing.T) {
	t.Parallel()
	families := []struct {
		name     string
		classify identifierClassifier
		routes   []identifierCollectionRoute
	}{
		{
			name:     "containers",
			classify: containerIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/containers/json", resourceMethod: http.MethodPost, resourcePath: "/containers/json/start", resourceIdentifier: "json"},
				{name: "head list", method: http.MethodHead, path: "/containers/json", resourceMethod: http.MethodPost, resourcePath: "/containers/json/start", resourceIdentifier: "json"},
				{name: "create", method: http.MethodPost, path: "/containers/create", resourceMethod: http.MethodGet, resourcePath: "/containers/create/json", resourceIdentifier: "create"},
				{name: "prune", method: http.MethodPost, path: "/containers/prune", resourceMethod: http.MethodGet, resourcePath: "/containers/prune/json", resourceIdentifier: "prune"},
			},
		},
		{
			name:     "images",
			classify: imageIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/images/json", resourceMethod: http.MethodDelete, resourcePath: "/images/json", resourceIdentifier: "json"},
				{name: "head list", method: http.MethodHead, path: "/images/json", resourceMethod: http.MethodDelete, resourcePath: "/images/json", resourceIdentifier: "json"},
				{name: "get search", method: http.MethodGet, path: "/images/search", resourceMethod: http.MethodDelete, resourcePath: "/images/search", resourceIdentifier: "search"},
				{name: "head search", method: http.MethodHead, path: "/images/search", resourceMethod: http.MethodDelete, resourcePath: "/images/search", resourceIdentifier: "search"},
				{name: "get batch export", method: http.MethodGet, path: "/images/get", resourceMethod: http.MethodDelete, resourcePath: "/images/get", resourceIdentifier: "get"},
				{name: "head batch export", method: http.MethodHead, path: "/images/get", resourceMethod: http.MethodDelete, resourcePath: "/images/get", resourceIdentifier: "get"},
				{name: "create", method: http.MethodPost, path: "/images/create", resourceMethod: http.MethodDelete, resourcePath: "/images/create", resourceIdentifier: "create"},
				{name: "load", method: http.MethodPost, path: "/images/load", resourceMethod: http.MethodDelete, resourcePath: "/images/load", resourceIdentifier: "load"},
				{name: "prune", method: http.MethodPost, path: "/images/prune", resourceMethod: http.MethodDelete, resourcePath: "/images/prune", resourceIdentifier: "prune"},
			},
		},
		{
			name:     "networks",
			classify: networkIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/networks"},
				{name: "head list", method: http.MethodHead, path: "/networks"},
				{name: "create", method: http.MethodPost, path: "/networks/create", resourceMethod: http.MethodGet, resourcePath: "/networks/create", resourceIdentifier: "create"},
				{name: "prune", method: http.MethodPost, path: "/networks/prune", resourceMethod: http.MethodGet, resourcePath: "/networks/prune", resourceIdentifier: "prune"},
			},
		},
		{
			name:     "volumes",
			classify: volumeIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/volumes"},
				{name: "head list", method: http.MethodHead, path: "/volumes"},
				{name: "create", method: http.MethodPost, path: "/volumes/create", resourceMethod: http.MethodGet, resourcePath: "/volumes/create", resourceIdentifier: "create"},
				{name: "prune", method: http.MethodPost, path: "/volumes/prune", resourceMethod: http.MethodGet, resourcePath: "/volumes/prune", resourceIdentifier: "prune"},
			},
		},
		{
			name:     "services",
			classify: serviceIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/services"},
				{name: "head list", method: http.MethodHead, path: "/services"},
				{name: "create", method: http.MethodPost, path: "/services/create", resourceMethod: http.MethodGet, resourcePath: "/services/create", resourceIdentifier: "create"},
			},
		},
		{
			name: "tasks",
			classify: func(_ string, path string) (string, bool) {
				return taskIdentifier(path)
			},
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/tasks"},
				{name: "head list", method: http.MethodHead, path: "/tasks"},
			},
		},
		{
			name:     "secrets",
			classify: secretIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/secrets"},
				{name: "head list", method: http.MethodHead, path: "/secrets"},
				{name: "create", method: http.MethodPost, path: "/secrets/create", resourceMethod: http.MethodGet, resourcePath: "/secrets/create", resourceIdentifier: "create"},
			},
		},
		{
			name:     "configs",
			classify: configIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/configs"},
				{name: "head list", method: http.MethodHead, path: "/configs"},
				{name: "create", method: http.MethodPost, path: "/configs/create", resourceMethod: http.MethodGet, resourcePath: "/configs/create", resourceIdentifier: "create"},
			},
		},
		{
			name: "nodes",
			classify: func(_ string, path string) (string, bool) {
				return nodeIdentifier(path)
			},
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/nodes"},
				{name: "head list", method: http.MethodHead, path: "/nodes"},
			},
		},
	}

	for _, family := range families {
		t.Run(family.name, func(t *testing.T) {
			t.Parallel()
			testIdentifierCollectionRoutes(t, family.classify, family.routes)
		})
	}
}

func TestLibpodCollectionRoutesAreNotResourceIdentifiers(t *testing.T) {
	t.Parallel()
	families := []struct {
		name     string
		classify identifierClassifier
		routes   []identifierCollectionRoute
	}{
		{
			name:     "containers",
			classify: libpodContainerIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/libpod/containers/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/containers/json", resourceIdentifier: "json"},
				{name: "head list", method: http.MethodHead, path: "/libpod/containers/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/containers/json", resourceIdentifier: "json"},
				{name: "get show mounted", method: http.MethodGet, path: "/libpod/containers/showmounted", resourceMethod: http.MethodDelete, resourcePath: "/libpod/containers/showmounted", resourceIdentifier: "showmounted"},
				{name: "head show mounted", method: http.MethodHead, path: "/libpod/containers/showmounted", resourceMethod: http.MethodDelete, resourcePath: "/libpod/containers/showmounted", resourceIdentifier: "showmounted"},
				{name: "get stats", method: http.MethodGet, path: "/libpod/containers/stats", resourceMethod: http.MethodDelete, resourcePath: "/libpod/containers/stats", resourceIdentifier: "stats"},
				{name: "head stats", method: http.MethodHead, path: "/libpod/containers/stats", resourceMethod: http.MethodDelete, resourcePath: "/libpod/containers/stats", resourceIdentifier: "stats"},
				{name: "create", method: http.MethodPost, path: "/libpod/containers/create", resourceMethod: http.MethodGet, resourcePath: "/libpod/containers/create/json", resourceIdentifier: "create"},
				{name: "prune", method: http.MethodPost, path: "/libpod/containers/prune", resourceMethod: http.MethodGet, resourcePath: "/libpod/containers/prune/json", resourceIdentifier: "prune"},
			},
		},
		{
			name:     "images",
			classify: libpodImageIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/libpod/images/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/images/json", resourceIdentifier: "json"},
				{name: "head list", method: http.MethodHead, path: "/libpod/images/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/images/json", resourceIdentifier: "json"},
				{name: "get search", method: http.MethodGet, path: "/libpod/images/search", resourceMethod: http.MethodDelete, resourcePath: "/libpod/images/search", resourceIdentifier: "search"},
				{name: "head search", method: http.MethodHead, path: "/libpod/images/search", resourceMethod: http.MethodDelete, resourcePath: "/libpod/images/search", resourceIdentifier: "search"},
				{name: "get batch export", method: http.MethodGet, path: "/libpod/images/export", resourceMethod: http.MethodDelete, resourcePath: "/libpod/images/export", resourceIdentifier: "export"},
				{name: "head batch export", method: http.MethodHead, path: "/libpod/images/export", resourceMethod: http.MethodDelete, resourcePath: "/libpod/images/export", resourceIdentifier: "export"},
				{name: "load", method: http.MethodPost, path: "/libpod/images/load", resourceMethod: http.MethodDelete, resourcePath: "/libpod/images/load", resourceIdentifier: "load"},
				{name: "import", method: http.MethodPost, path: "/libpod/images/import", resourceMethod: http.MethodDelete, resourcePath: "/libpod/images/import", resourceIdentifier: "import"},
				{name: "pull", method: http.MethodPost, path: "/libpod/images/pull", resourceMethod: http.MethodDelete, resourcePath: "/libpod/images/pull", resourceIdentifier: "pull"},
				{name: "prune", method: http.MethodPost, path: "/libpod/images/prune", resourceMethod: http.MethodDelete, resourcePath: "/libpod/images/prune", resourceIdentifier: "prune"},
				{name: "remove", method: http.MethodDelete, path: "/libpod/images/remove", resourceMethod: http.MethodGet, resourcePath: "/libpod/images/remove/json", resourceIdentifier: "remove"},
			},
		},
		{
			name:     "pods",
			classify: libpodPodIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/libpod/pods/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/pods/json", resourceIdentifier: "json"},
				{name: "head list", method: http.MethodHead, path: "/libpod/pods/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/pods/json", resourceIdentifier: "json"},
				{name: "get stats", method: http.MethodGet, path: "/libpod/pods/stats", resourceMethod: http.MethodDelete, resourcePath: "/libpod/pods/stats", resourceIdentifier: "stats"},
				{name: "head stats", method: http.MethodHead, path: "/libpod/pods/stats", resourceMethod: http.MethodDelete, resourcePath: "/libpod/pods/stats", resourceIdentifier: "stats"},
				{name: "create", method: http.MethodPost, path: "/libpod/pods/create", resourceMethod: http.MethodGet, resourcePath: "/libpod/pods/create/json", resourceIdentifier: "create"},
				{name: "prune", method: http.MethodPost, path: "/libpod/pods/prune", resourceMethod: http.MethodGet, resourcePath: "/libpod/pods/prune/json", resourceIdentifier: "prune"},
			},
		},
		{
			name:     "networks",
			classify: libpodNetworkIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/libpod/networks/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/networks/json", resourceIdentifier: "json"},
				{name: "head list", method: http.MethodHead, path: "/libpod/networks/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/networks/json", resourceIdentifier: "json"},
				{name: "create", method: http.MethodPost, path: "/libpod/networks/create", resourceMethod: http.MethodGet, resourcePath: "/libpod/networks/create/json", resourceIdentifier: "create"},
				{name: "prune", method: http.MethodPost, path: "/libpod/networks/prune", resourceMethod: http.MethodGet, resourcePath: "/libpod/networks/prune/json", resourceIdentifier: "prune"},
			},
		},
		{
			name:     "volumes",
			classify: libpodVolumeIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/libpod/volumes/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/volumes/json", resourceIdentifier: "json"},
				{name: "head list", method: http.MethodHead, path: "/libpod/volumes/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/volumes/json", resourceIdentifier: "json"},
				{name: "create", method: http.MethodPost, path: "/libpod/volumes/create", resourceMethod: http.MethodGet, resourcePath: "/libpod/volumes/create/json", resourceIdentifier: "create"},
				{name: "prune", method: http.MethodPost, path: "/libpod/volumes/prune", resourceMethod: http.MethodGet, resourcePath: "/libpod/volumes/prune/json", resourceIdentifier: "prune"},
			},
		},
		{
			name:     "secrets",
			classify: libpodSecretIdentifier,
			routes: []identifierCollectionRoute{
				{name: "get list", method: http.MethodGet, path: "/libpod/secrets/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/secrets/json", resourceIdentifier: "json"},
				{name: "head list", method: http.MethodHead, path: "/libpod/secrets/json", resourceMethod: http.MethodDelete, resourcePath: "/libpod/secrets/json", resourceIdentifier: "json"},
				{name: "create", method: http.MethodPost, path: "/libpod/secrets/create", resourceMethod: http.MethodGet, resourcePath: "/libpod/secrets/create/json", resourceIdentifier: "create"},
			},
		},
	}

	for _, family := range families {
		t.Run(family.name, func(t *testing.T) {
			t.Parallel()
			testIdentifierCollectionRoutes(t, family.classify, family.routes)
		})
	}
}
