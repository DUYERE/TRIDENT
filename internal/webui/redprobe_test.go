package webui

import "testing"

// Intentional red gate probe for the P2-1 acceptance drill: proves the CI gate
// can fail closed on a real runner. Reverted in the very next commit once the
// red run is recorded.
func TestIntentionalRedGateProbe(t *testing.T) {
	t.Fatal("intentional red: the offline gate must fail closed (P2-1 drill, reverted next)")
}
