package validation

import (
	"strings"
	"testing"
)

// Bundle-9 / Audit L-012 / CWE-1007 + CWE-176 regression suite.
//
// Note: invisible / formatting characters in test inputs are written as
// \uXXXX escape sequences (NOT literal codepoints) so the source file
// stays parseable + readable. Literal BOM / RTL-override bytes inside
// a Go string literal trip the parser ("illegal byte order mark").

func TestValidateUnicodeSafe_AcceptsCleanASCII(t *testing.T) {
	cases := []string{
		"example.com",
		"api.example.com",
		"sub-domain.example.co.uk",
		"a.b.c.d.example.org",
		"localhost",
		"192.168.1.1",
		"",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if err := ValidateUnicodeSafe(c); err != nil {
				t.Errorf("clean ASCII %q rejected: %v", c, err)
			}
		})
	}
}

func TestValidateUnicodeSafe_RejectsRTLOverride(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"LRE", "good‪com"},
		{"RLE", "good‫com"},
		{"PDF", "good‬com"},
		{"LRO", "good‭com"},
		{"RLO", "good‮com"},
		{"LRI", "good⁦com"},
		{"RLI", "good⁧com"},
		{"FSI", "good⁨com"},
		{"PDI", "good⁩com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateUnicodeSafe(c.in)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), "bidirectional override") {
				t.Errorf("error should cite bidirectional override; got: %v", err)
			}
		})
	}
}

func TestValidateUnicodeSafe_RejectsZeroWidth(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"ZWSP", "good​com"},
		{"ZWNJ", "good‌com"},
		{"ZWJ", "good‍com"},
		{"WJ", "good⁠com"},
		{"BOM", "good\uFEFFcom"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateUnicodeSafe(c.in)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), "zero-width") {
				t.Errorf("error should cite zero-width; got: %v", err)
			}
		})
	}
}

func TestValidateUnicodeSafe_RejectsControlChars(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"NUL", "good\x00com"},
		{"TAB", "good\tcom"},
		{"LF", "good\ncom"},
		{"CR", "good\rcom"},
		{"DEL", "good\x7Fcom"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateUnicodeSafe(c.in)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), "control character") {
				t.Errorf("error should cite control character; got: %v", err)
			}
		})
	}
}

func TestValidateUnicodeSafe_RejectsIDNHomograph(t *testing.T) {
	// Cyrillic 'а' (U+0430) inside an otherwise-Latin label — visually
	// identical to Latin 'a' but a different codepoint. Classic homograph.
	cases := []struct {
		name string
		in   string
	}{
		{"cyrillic_a_in_apple", "аpple.com"},
		{"greek_omicron_in_google", "gοogle.com"},
		{"cherokee_letter", "gᏇogle.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateUnicodeSafe(c.in)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), "IDN homograph") {
				t.Errorf("error should cite IDN homograph; got: %v", err)
			}
		})
	}
}

func TestValidateUnicodeSafe_AcceptsPureNonASCII(t *testing.T) {
	// A fully-Cyrillic label is a legitimate IDN — don't reject. The
	// homograph attack we're defending against is the MIX with ASCII.
	in := "пример.рф"
	if err := ValidateUnicodeSafe(in); err != nil {
		t.Errorf("pure-Cyrillic label rejected: %v", err)
	}
}

func TestValidateUnicodeSafe_ErrorMentionsByteOffset(t *testing.T) {
	in := "good‮evil.com"
	err := ValidateUnicodeSafe(in)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), "byte offset") {
		t.Errorf("error should cite byte offset; got: %v", err)
	}
}

func TestValidateUnicodeSafe_EmptyStringPasses(t *testing.T) {
	if err := ValidateUnicodeSafe(""); err != nil {
		t.Errorf("empty string should pass through (different validator handles required); got: %v", err)
	}
}
