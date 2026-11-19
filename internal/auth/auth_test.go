package auth

import (
	"strings"
	"testing"
)

func TestRoleOrder(t *testing.T) {
	allowed := map[Role][]Role{Viewer: {Viewer}, Operator: {Viewer, Operator}, Admin: {Viewer, Operator, Admin}}
	for have, mins := range allowed {
		for _, min := range []Role{Viewer, Operator, Admin} {
			want := false
			for _, m := range mins {
				want = want || m == min
			}
			if have.Allows(min) != want {
				t.Errorf("%s.Allows(%s) = %v", have, min, !want)
			}
		}
	}
	// Unbekannte oder leere Rollen erlauben nichts.
	if Role("").Allows(Viewer) || Role("root").Allows(Viewer) || Admin.Allows(Role("")) {
		t.Error("unbekannte Rolle darf nichts erlauben")
	}
	if !ValidRole("operator") || ValidRole("superuser") {
		t.Error("ValidRole falsch")
	}
}

func TestTokens(t *testing.T) {
	full, hash, err := NewToken("01HX")
	if err != nil {
		t.Fatal(err)
	}
	id, secret, ok := ParseToken(full)
	if !ok || id != "01HX" || len(secret) < 43 || strings.ContainsAny(secret, "_-+/=") {
		t.Fatalf("ParseToken(%q) = %q %q %v", full, id, secret, ok)
	}
	if !TokenMatches(secret, hash) || TokenMatches(secret+"x", hash) || TokenMatches("", hash) {
		t.Error("TokenMatches falsch")
	}
	other, _, _ := NewToken("01HX")
	if other == full {
		t.Error("Tokens muessen zufaellig sein")
	}
	for _, bad := range []string{"", "nrp_", "nrp_id", "nrp__secret", "xyz_id_secret", "Bearer nrp_a_b"} {
		if _, _, ok := ParseToken(bad); ok {
			t.Errorf("%q sollte abgelehnt werden", bad)
		}
	}
	if (Identity{Type: TypeMTLS}).IsLocal() || !(Identity{Type: TypeLocal}).IsLocal() || !(Identity{Type: TypeOffline}).IsLocal() {
		t.Error("IsLocal falsch")
	}
}
