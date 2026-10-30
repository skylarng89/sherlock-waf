package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReferencesListEveryPointerWithItsPath(t *testing.T) {
	root, err := Parse([]byte(`
schema_version: 1
global: { defaults: { block_page: { template_id: corp } } }
sites:
  - id: a
    hosts: [a.example.test]
    tls: { mode: file, cert_id: CERT1 }
    upstreams: { targets: ["h:443"], tls: { enabled: true, client_cert_id: CLIENT1 } }
    policy: { block_page: { template_id: corp } }
    endpoints:
      - { id: login, match: { path: /login }, policy: { block_page: { template_id: strict } } }
      - { id: plain, match: { path: /plain }, policy: { block_page: { template_id: default } } }
  - id: b
    hosts: [b.example.test]
    tls: { mode: file, cert_id: CERT1 }
    upstreams: { targets: ["h:1"] }
`))
	require.NoError(t, err)
	refs := root.References()

	assert.Equal(t, []string{"/sites/0/tls/cert_id", "/sites/1/tls/cert_id"}, refs.Certificates["CERT1"])
	assert.Equal(t, []string{"/sites/0/upstreams/tls/client_cert_id"}, refs.Certificates["CLIENT1"])
	assert.Equal(t, []string{"/global/defaults/block_page/template_id", "/sites/0/policy/block_page/template_id"}, refs.BlockPages["corp"])
	assert.Equal(t, []string{"/sites/0/endpoints/0/policy/block_page/template_id"}, refs.BlockPages["strict"])
	assert.NotContains(t, refs.BlockPages, "default", "the built-in page is not a stored object")
}
