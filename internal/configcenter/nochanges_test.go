package configcenter

import (
	"errors"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestPublishNoChangesSkipsRevision: publishing a config identical to the
// active revision returns ErrNoChanges, keeps the active revision id and
// appends nothing. Rollback to identical content still creates a revision
// (explicit point-in-time marker, allowNoChanges bypasses the check).
func TestPublishNoChangesSkipsRevision(t *testing.T) {
	c, err := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	rev, err := c.Publish(seedCfg(), "tester", "identical to rev 1")
	if !errors.Is(err, ErrNoChanges) {
		t.Fatalf("err = %v, want ErrNoChanges", err)
	}
	if rev != 1 {
		t.Fatalf("returned rev = %d, want active revision 1", rev)
	}
	cur, _ := c.Current()
	if cur != 1 {
		t.Fatalf("active rev = %d, want 1", cur)
	}
	revs, rerr := c.Store().ListRevisions(10)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(revs) != 1 {
		t.Fatalf("revision count = %d, want 1 (no new revision appended)", len(revs))
	}

	// A real change still publishes normally.
	rev2, err := c.Publish(twoSiteCfg(), "tester", "add site b")
	if err != nil {
		t.Fatal(err)
	}
	if rev2 != 2 {
		t.Fatalf("changed publish rev = %d, want 2", rev2)
	}

	// Rollback to identical content (rev 2 content == current rev 3 content
	// after rolling back to 1): must still append a new revision.
	rev3, err := c.Rollback(1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rev3 != 3 {
		t.Fatalf("rollback rev = %d, want 3", rev3)
	}
	rev4, err := c.Rollback(2, "admin")
	if err != nil {
		t.Fatalf("rollback to identical content failed: %v", err)
	}
	if rev4 != 4 {
		t.Fatalf("rollback-to-identical rev = %d, want 4 (always appends)", rev4)
	}
	_, cfg := c.Current()
	if len(cfg.Sites) != 2 {
		t.Fatalf("rollback content wrong: sites=%d, want 2", len(cfg.Sites))
	}
}

// TestPublishNoChangesIgnoresEmptyContainers: console forms round-trip absent
// sections as empty containers (e.g. an edited site carries "security":{}).
// A publish differing from the active revision only by empty objects/arrays
// is behaviorally identical and must not create a new revision.
func TestPublishNoChangesIgnoresEmptyContainers(t *testing.T) {
	c, err := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	withEmpty := seedCfg()
	for i := range withEmpty.Sites {
		if withEmpty.Sites[i].Security == nil {
			withEmpty.Sites[i].Security = &config.SecuritySettings{}
		}
	}
	rev, err := c.Publish(withEmpty, "tester", "only empty containers added")
	if !errors.Is(err, ErrNoChanges) {
		t.Fatalf("err = %v, want ErrNoChanges", err)
	}
	if rev != 1 {
		t.Fatalf("returned rev = %d, want 1", rev)
	}
	revs, rerr := c.Store().ListRevisions(10)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(revs) != 1 {
		t.Fatalf("revision count = %d, want 1 (empty-container diff must not append)", len(revs))
	}
}
