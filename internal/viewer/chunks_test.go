package viewer_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ryanymt/mercurio-project/internal/viewer"
)

// The viewer reads the artifacts bucket through Cloud Storage's JSON API as its own account, with
// objectViewer's two rights: list a prefix (its own segment, "/"-ended, so transcript never matches
// transcript2) and get an object, each bounded. An error names the status, never the token.
func TestTheGCSReader(t *testing.T) {
	const token = "ya29.the-viewer-access-token"
	objects := map[string]string{
		"p/t/transcript/000001.jsonl":  "one\n",
		"p/t/transcript/000002.jsonl":  "two two two\n",
		"p/t/transcript/000003.jsonl":  "three\n",
		"p/t/transcript2/000001.jsonl": "another prefix\n",
	}
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"error":{"code":401}}`, http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/storage/v1/b/arts/o":
			prefix := r.URL.Query().Get("prefix")
			var items []map[string]any
			for _, n := range []string{"p/t/transcript/000001.jsonl", "p/t/transcript/000002.jsonl", "p/t/transcript/000003.jsonl", "p/t/transcript2/000001.jsonl"} {
				if strings.HasPrefix(n, prefix) {
					items = append(items, map[string]any{"name": n, "size": fmt.Sprint(len(objects[n]))})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"items": items})
		case strings.HasPrefix(r.URL.Path, "/storage/v1/b/arts/o/") && r.URL.Query().Get("alt") == "media":
			name := strings.TrimPrefix(r.URL.Path, "/storage/v1/b/arts/o/")
			data, ok := objects[name]
			if !ok {
				http.Error(w, `{"error":{"code":404}}`, http.StatusNotFound)
				return
			}
			fmt.Fprint(w, data)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	tokens := func(context.Context) (string, error) { return token, nil }
	for _, u := range []string{"http://storage.googleapis.com", ""} {
		if _, err := viewer.NewGCSChunks(u, "arts", tokens, nil); err == nil {
			t.Errorf("endpoint %q accepted", u)
		}
	}
	g, err := viewer.NewGCSChunks(srv.URL, "arts", tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	objs, more, err := g.List(ctx, "p/t/transcript", 2)
	if err != nil || len(objs) != 2 || !more || objs[0].Name != "p/t/transcript/000001.jsonl" || objs[1].Size != 12 {
		t.Fatalf("list: %+v, more %v, %v", objs, more, err)
	}
	all, more, _ := g.List(ctx, "p/t/transcript", 10)
	if len(all) != 3 || more {
		t.Fatalf("list of 10: %d objects, more %v: the /-ended prefix keeps transcript2 out", len(all), more)
	}
	data, cut, err := g.Read(ctx, "p/t/transcript/000002.jsonl", 5)
	if err != nil || string(data) != "two t" || !cut {
		t.Fatalf("read bounded: %q, cut %v, %v", data, cut, err)
	}
	data, cut, err = g.Read(ctx, "p/t/transcript/000001.jsonl", 100)
	if err != nil || string(data) != "one\n" || cut {
		t.Fatalf("read whole: %q, cut %v, %v", data, cut, err)
	}
	if _, _, err := g.Read(ctx, "p/t/transcript/missing.jsonl", 10); err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("a missing object: %v", err)
	}
	bad, _ := viewer.NewGCSChunks(srv.URL, "arts", func(context.Context) (string, error) { return "wrong", nil }, nil)
	if _, _, err := bad.List(ctx, "p", 1); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a refused list: %v", err)
	}
}
