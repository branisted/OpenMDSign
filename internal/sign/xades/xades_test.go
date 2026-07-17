package xades

import (
	"crypto"
	"testing"

	"github.com/branistedev/openmdsign/internal/sign"
)

func TestResolvePackaging(t *testing.T) {
	cases := map[sign.Packaging]string{
		sign.PackagingDetached:   "DETACHED",
		"":                       "DETACHED",
		sign.PackagingEnveloping: "ENVELOPING",
	}
	for in, wantDSS := range cases {
		_, dss, err := resolvePackaging(in)
		if err != nil {
			t.Fatalf("resolvePackaging(%q) unexpected error: %v", in, err)
		}
		if dss != wantDSS {
			t.Errorf("resolvePackaging(%q) = %q, want %q", in, dss, wantDSS)
		}
	}
	if _, _, err := resolvePackaging("bogus"); err == nil {
		t.Error("resolvePackaging(bogus) expected error, got nil")
	}
}

func TestResolveDigest(t *testing.T) {
	h, dss, err := resolveDigest("")
	if err != nil || h != crypto.SHA256 || dss != "SHA256" {
		t.Fatalf("resolveDigest(\"\") = %v,%q,%v; want SHA256,SHA256,nil", h, dss, err)
	}
	h, dss, err = resolveDigest("sha1")
	if err != nil || h != crypto.SHA1 || dss != "SHA1" {
		t.Fatalf("resolveDigest(sha1) = %v,%q,%v; want SHA1,SHA1,nil", h, dss, err)
	}
	if _, _, err := resolveDigest("md5"); err == nil {
		t.Error("resolveDigest(md5) expected error")
	}
}

func TestResolveLevel(t *testing.T) {
	name, ts, err := resolveLevel(sign.LevelB)
	if err != nil || name != "XAdES_BASELINE_B" || ts {
		t.Fatalf("resolveLevel(b) = %q,%v,%v; want XAdES_BASELINE_B,false,nil", name, ts, err)
	}
	name, ts, err = resolveLevel(sign.LevelT)
	if err != nil || name != "XAdES_BASELINE_T" || !ts {
		t.Fatalf("resolveLevel(t) = %q,%v,%v; want XAdES_BASELINE_T,true,nil", name, ts, err)
	}
	if _, _, err := resolveLevel("x"); err == nil {
		t.Error("resolveLevel(x) expected error")
	}
}

func TestMimeTypeFor(t *testing.T) {
	cases := map[string]string{
		"a.pdf":  "application/pdf",
		"a.txt":  "text/plain",
		"a.bin":  "application/octet-stream",
		"noext":  "application/octet-stream",
		"a.json": "application/json",
	}
	for name, want := range cases {
		if got := mimeTypeFor(name); got != want {
			t.Errorf("mimeTypeFor(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestProfileName(t *testing.T) {
	if New("").Profile() != "XAdES" {
		t.Errorf("Profile() = %q, want XAdES", New("").Profile())
	}
}
