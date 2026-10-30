package config

import "strconv"

// Refs lists, for each stored object a configuration points at, the JSON
// pointers of the fields that point at it. Stored objects live outside the
// configuration document (uploaded certificates, block page templates), so
// existence is checked by whoever owns the store, and deletion is refused while
// a live configuration still uses one.
type Refs struct {
	Certificates map[string][]string
	BlockPages   map[string][]string
	OpenAPIDocs  map[string][]string
	CACerts      map[string][]string
}

// References collects every reference in r. The built-in block page
// ("default") is not a stored object and is not listed.
func (r *Root) References() Refs {
	refs := Refs{Certificates: map[string][]string{}, BlockPages: map[string][]string{}, OpenAPIDocs: map[string][]string{}, CACerts: map[string][]string{}}
	cert := func(id, path string) {
		if id != "" {
			refs.Certificates[id] = append(refs.Certificates[id], path)
		}
	}
	page := func(pol *BlockPage, path string) {
		if pol != nil && pol.TemplateID != nil && *pol.TemplateID != DefaultBlockPageTemplate {
			refs.BlockPages[*pol.TemplateID] = append(refs.BlockPages[*pol.TemplateID], path)
		}
	}
	api := func(pol *APIPolicy, path string) {
		if pol == nil {
			return
		}
		if pol.OpenAPIDocID != "" {
			refs.OpenAPIDocs[pol.OpenAPIDocID] = append(refs.OpenAPIDocs[pol.OpenAPIDocID], path+"/openapi_doc_id")
		}
		if pol.MTLS != nil && pol.MTLS.CACertID != "" {
			refs.CACerts[pol.MTLS.CACertID] = append(refs.CACerts[pol.MTLS.CACertID], path+"/mtls/ca_cert_id")
		}
	}
	api(r.Global.Defaults.API, "/global/defaults/api")
	page(r.Global.Defaults.BlockPage, "/global/defaults/block_page/template_id")
	for i, s := range r.Sites {
		sp := "/sites/" + strconv.Itoa(i)
		cert(s.TLS.CertID, sp+"/tls/cert_id")
		cert(s.Upstreams.TLS.ClientCertID, sp+"/upstreams/tls/client_cert_id")
		page(s.Policy.BlockPage, sp+"/policy/block_page/template_id")
		api(s.Policy.API, sp+"/policy/api")
		for j, e := range s.Endpoints {
			page(e.Policy.BlockPage, sp+"/endpoints/"+strconv.Itoa(j)+"/policy/block_page/template_id")
			api(e.Policy.API, sp+"/endpoints/"+strconv.Itoa(j)+"/policy/api")
		}
	}
	return refs
}
