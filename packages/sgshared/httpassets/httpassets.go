package httpassets

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
)

// Package httpassets serves an embedded asset tree with cache headers that let
// a browser keep what it already has.
//
// Static assets were served with no caching headers at all, so a browser
// re-downloaded every one of them on every page change.
//
// That is 1.2 MB across 28 files, and it is the whole reason moving between
// pages felt like loading a different site: this app is server-rendered, so each
// navigation is a real document, and without a validator the browser has no way
// to know the JavaScript it already holds is still current. http.FileServer does
// not fill the gap on its own — the assets are //go:embed'ed and embedded files
// have a zero modtime, so ServeContent omits Last-Modified and there is nothing
// left to revalidate against.
//
// Two policies, because there are two kinds of file here:
//
//   - Content-addressed (chunks/metal-octocat-JSSBITFR.js). The name changes
//     when the bytes change, so it can be cached for a year and never
//     revalidated. This is where the 1.2 MB lives.
//   - Everything else (app.css, htmx.min.js, audit.js). Rebuilt IN PLACE, so an
//     immutable cache would be a stale stylesheet nobody can clear. An hour,
//     plus an ETag so the request after that hour is a 304 of a few hundred
//     bytes rather than the file again.
//
// The ETags are computed once at startup from the embedded bytes. Go's
// ServeContent honours If-None-Match against whatever ETag is already on the
// response, so setting the header here is enough to get 304s — no separate
// conditional-request handling.
//
// It lives here rather than in each app because it is the same forty lines in
// every one of them, and this repo has already paid twice for keeping two copies
// of something in step by hand.

// contentHashed matches esbuild's output naming: a base name, a dash, and the
// hash it appends. Deliberately narrow — a file called `my-CONSTANT.js` that is
// not content-addressed would be cached for a year, and the only way back is a
// rename.
var ContentHashed = regexp.MustCompile(`-[A-Z0-9]{8}\.(js|css)$`)

const (
	ImmutableCache = "public, max-age=31536000, immutable"
	// Revalidate every time, and let the ETag turn that into a 304.
	//
	// This was an hour, on the reasoning that a theme change landing "on the
	// next reload" was soon enough. It is not: shell.js is here too, and an hour
	// means a JavaScript fix reaches nobody for an hour — a browser with a fresh
	// copy does not ask the server at all, so a deploy that is verifiably live
	// looks broken to the person who reported the bug. That happened twice in a
	// row before the cause was found.
	//
	// The cost is one conditional request per unhashed asset per page load,
	// answered with a few hundred bytes. There are a handful of them; everything
	// with weight is content-addressed and still immutable above.
	RevalidateCache = "public, no-cache"
)

// Handler serves an embedded tree with the headers above.
type Handler struct {
	next  http.Handler
	etags map[string]string // path within the FS -> quoted ETag
}

func New(files fs.FS, next http.Handler) *Handler {
	c := &Handler{next: next, etags: map[string]string{}}
	_ = fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(files, p)
		if err != nil {
			// A file that cannot be read here simply gets no ETag; it is still
			// served, just always in full.
			return nil
		}
		sum := sha256.Sum256(b)
		c.etags[p] = `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`
		return nil
	})
	return c
}

func (c *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The handler underneath has the prefix stripped already, so the lookup key
	// is the request path without its leading slash — the same shape WalkDir
	// produced.
	key := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")

	if ContentHashed.MatchString(key) {
		w.Header().Set("Cache-Control", ImmutableCache)
	} else {
		w.Header().Set("Cache-Control", RevalidateCache)
	}
	if tag, ok := c.etags[key]; ok {
		w.Header().Set("ETag", tag)
	}
	c.next.ServeHTTP(w, r)
}
