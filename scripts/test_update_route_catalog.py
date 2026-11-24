import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "update-route-catalog.py"
spec = importlib.util.spec_from_file_location("update_route_catalog", SCRIPT)
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)

PLAIN = '''
func (s *APIServer) registerX(r *mux.Router) error {
	// swagger:operation GET /ignored
	r.Handle(VersionedPath("/things"), s.APIHandler(a.List)).Methods(http.MethodGet)
	r.Handle("/things", s.APIHandler(a.List)).Methods(http.MethodGet)
	r.Handle(VersionedPath("/plugins"), s.APIHandler(compat.UnsupportedHandler))
	return nil
}
'''

HANDLEFUNC = '''
	r.HandleFunc(VersionedPath("/libpod/autoupdate"), s.APIHandler(libpod.AutoUpdate)).Methods(http.MethodPost)
	r.HandleFunc("/containers/{name}/archive", s.APIHandler(compat.Archive)).Methods(http.MethodGet, http.MethodPut, http.MethodHead)
'''

SUBROUTER = '''
	v3 := r.PathPrefix("/v{version:[0-3][0-9A-Za-z.-]*}/libpod/manifests").Subrouter()
	v4 := r.PathPrefix("/v{version:[4-9][0-9A-Za-z.-]*}/libpod/manifests").Subrouter()
	v3.Handle("/create", s.APIHandler(libpod.ManifestCreate)).Methods(http.MethodPost)
	v4.Handle("/{name:.*}", s.APIHandler(libpod.ManifestModify)).Methods(http.MethodPut)
	v4.HandleFunc("/{name:.*}/json", s.APIHandler(libpod.ManifestInspect)).Methods(http.MethodGet)
'''

STUBS = '''
	r.PathPrefix("/v{version:[0-9.]+}/configs/").HandlerFunc(noSwarm)
	r.PathPrefix("/configs/").HandlerFunc(noSwarm)
'''


class ParsePodmanRegister(unittest.TestCase):
    def test_plain_handle_skips_unsupported_and_comments(self):
        self.assertEqual(catalog.parse_podman_register(PLAIN, "x.go"), {("GET", "/things")})

    def test_handlefunc_and_multiple_methods(self):
        self.assertEqual(
            catalog.parse_podman_register(HANDLEFUNC, "x.go"),
            {("POST", "/libpod/autoupdate"), ("GET", "/containers/{name}/archive"), ("PUT", "/containers/{name}/archive"), ("HEAD", "/containers/{name}/archive")},
        )

    def test_subrouter_prefix_is_prepended_without_version(self):
        self.assertEqual(
            catalog.parse_podman_register(SUBROUTER, "x.go"),
            {("POST", "/libpod/manifests/create"), ("PUT", "/libpod/manifests/{name:.*}"), ("GET", "/libpod/manifests/{name:.*}/json")},
        )

    def test_catch_all_prefix_stubs_are_not_routes(self):
        self.assertEqual(catalog.parse_podman_register(STUBS, "x.go"), set())

    def test_prefix_handler_other_than_noswarm_fails(self):
        source = '\tr.PathPrefix("/libpod/new/").HandlerFunc(serveNew)\n'
        with self.assertRaisesRegex(ValueError, "subrouter format changed"):
            catalog.parse_podman_register(source, "x.go")

    def test_unknown_router_variable_fails(self):
        with self.assertRaises(ValueError):
            catalog.parse_podman_register('\tv9.Handle("/x", h).Methods(http.MethodGet)\n', "x.go")

    def test_unparsed_registration_style_fails_the_count_check(self):
        # Methods on the next line is a style the extractor does not parse.
        source = '\tr.Handle("/x", h).\n\t\tMethods(http.MethodGet)\n'
        with self.assertRaisesRegex(ValueError, "registration format changed"):
            catalog.parse_podman_register(source, "x.go")

    def test_unparsed_subrouter_declaration_fails(self):
        source = '\tv5 := r.PathPrefix("/libpod/x").Methods(http.MethodGet).Subrouter()\n'
        with self.assertRaisesRegex(ValueError, "subrouter format changed"):
            catalog.parse_podman_register(source, "x.go")

    def test_chained_subrouter_registration_fails(self):
        source = '\tr.PathPrefix("/libpod/x").Subrouter().Handle("/y", h).Methods(http.MethodGet)\n'
        with self.assertRaises(ValueError):
            catalog.parse_podman_register(source, "x.go")


class Render(unittest.TestCase):
    def test_output_is_sorted_and_stable(self):
        routes = {("POST", "/b"), ("GET", "/b"), ("GET", "/a")}
        first = catalog.render(routes, "u")
        self.assertEqual(first, catalog.render(set(reversed(sorted(routes))), "u"))
        self.assertLess(first.index('"/a"'), first.index('"/b"'))
        self.assertTrue(first.endswith("\n"))

    def test_podman_file_order_does_not_change_routes(self):
        a = catalog.parse_podman_register(PLAIN, "a.go") | catalog.parse_podman_register(SUBROUTER, "b.go")
        b = catalog.parse_podman_register(SUBROUTER, "b.go") | catalog.parse_podman_register(PLAIN, "a.go")
        self.assertEqual(catalog.render(a, "u"), catalog.render(b, "u"))


if __name__ == "__main__":
    unittest.main()
