package gosum

import "testing"

func TestParse(t *testing.T) {
	src := `github.com/foo/bar v1.2.3 h1:abcdef=
github.com/foo/bar v1.2.3/go.mod h1:ghijkl=
github.com/foo/baz v0.1.0 h1:mnopqr=
`
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(f.Entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(f.Entries))
	}
	if !f.Has("github.com/foo/bar", "v1.2.3") {
		t.Errorf("Has(bar, v1.2.3) = false")
	}
	if f.Has("github.com/foo/bar", "v9.9.9") {
		t.Errorf("Has(bar, v9.9.9) = true")
	}
	hash, ok := f.Hash("github.com/foo/baz", "v0.1.0")
	if !ok || hash != "h1:mnopqr=" {
		t.Errorf("Hash(baz) = %q, %v", hash, ok)
	}
	if !f.Entries[1].IsGoMod {
		t.Errorf("second entry should be a /go.mod line")
	}
}

func TestParseMalformedLine(t *testing.T) {
	_, err := Parse([]byte("onlytwo fields\n"))
	if err == nil {
		t.Fatal("expected an error for a malformed line")
	}
}

func TestNilFile(t *testing.T) {
	var f *File
	if f.Has("x", "v1.0.0") {
		t.Errorf("nil *File.Has should be false")
	}
	if _, ok := f.Hash("x", "v1.0.0"); ok {
		t.Errorf("nil *File.Hash should be !ok")
	}
}
