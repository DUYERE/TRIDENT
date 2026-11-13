//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"
	"trident/internal/store"
)

func drainEvents(t *testing.T, f *fixture) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		events, e := f.s.ClaimEvents(ctx, f.admin, "drain", 1000, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if len(events) == 0 {
			return
		}
		for _, ev := range events {
			if e = f.s.AckEvent(ctx, f.admin, ev.ID, ev.ClaimGeneration, "drain"); e != nil {
				t.Fatal(e)
			}
		}
	}
	t.Fatal("outbox drain exceeded safety bound")
}
func appendFixtureEvent(t *testing.T, f *fixture, aggregate int64, version int) int64 {
	t.Helper()
	var id int64
	e := f.p.QueryRow(context.Background(), `INSERT INTO outbox_events(task_id,aggregate_kind,aggregate_id,aggregate_version,event_type,payload) VALUES($1,'test',$2,$3,'synthetic','{}') RETURNING id`, f.task, aggregate, version).Scan(&id)
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func findEvent(events []store.OutboxEvent, id int64) (store.OutboxEvent, bool) {
	for _, e := range events {
		if e.ID == id {
			return e, true
		}
	}
	return store.OutboxEvent{}, false
}

func TestOutboxHeadOfLineFencingAndDeadLetter(t *testing.T) {
	f := setup(t)
	drainEvents(t, f)
	ctx := context.Background()
	first := appendFixtureEvent(t, f, 1, 1)
	second := appendFixtureEvent(t, f, 1, 2)
	events, e := f.s.ClaimEvents(ctx, f.reconciler, "dispatcher-a", 100, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	a, ok := findEvent(events, first)
	if !ok {
		t.Fatal("first aggregate event not claimed")
	}
	if _, ok = findEvent(events, second); ok {
		t.Fatal("claimed successor before predecessor")
	}
	next, e := f.s.ClaimEvents(ctx, f.reconciler, "dispatcher-b", 100, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok = findEvent(next, second); ok {
		t.Fatal("SKIP LOCKED bypassed aggregate head")
	}
	if e = f.s.FailEvent(ctx, f.reconciler, a.ID, a.ClaimGeneration, "dispatcher-a", "Bearer synthetic-secret", 1, 0); e != nil {
		t.Fatal(e)
	}
	next, e = f.s.ClaimEvents(ctx, f.reconciler, "dispatcher-b", 100, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok = findEvent(next, second); ok {
		t.Fatal("dead letter did not block successor")
	}
	var last string
	if e = f.p.QueryRow(ctx, `SELECT last_error FROM outbox_events WHERE id=$1`, first).Scan(&last); e != nil {
		t.Fatal(e)
	}
	if last == "Bearer synthetic-secret" {
		t.Fatal("error credential leaked")
	}
	if e = f.s.ReplayEvent(ctx, f.worker, first, "unauthorized"); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("worker replay=%v", e)
	}
	if e = f.s.ReplayEvent(ctx, f.admin, first, "notification replay only"); e != nil {
		t.Fatal(e)
	}
	next, e = f.s.ClaimEvents(ctx, f.reconciler, "dispatcher-b", 100, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	b, ok := findEvent(next, first)
	if !ok {
		t.Fatal("replayed head not claimed")
	}
	if e = f.s.AckEvent(ctx, f.reconciler, a.ID, a.ClaimGeneration, "dispatcher-a"); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("old generation ack=%v", e)
	}
	if e = f.s.AckEvent(ctx, f.reconciler, b.ID, b.ClaimGeneration, "dispatcher-b"); e != nil {
		t.Fatal(e)
	}
	next, e = f.s.ClaimEvents(ctx, f.reconciler, "dispatcher-c", 100, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	c, ok := findEvent(next, second)
	if !ok {
		t.Fatal("successor not unblocked")
	}
	if e = f.s.AckEvent(ctx, f.reconciler, c.ID, c.ClaimGeneration, "dispatcher-c"); e != nil {
		t.Fatal(e)
	}
	if e = f.s.AckEvent(ctx, f.reconciler, c.ID, c.ClaimGeneration, "dispatcher-c"); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("duplicate ack=%v", e)
	}
}

func TestOutboxAckRechecksExpiryAfterLock(t *testing.T) {
	f := setup(t)
	drainEvents(t, f)
	ctx := context.Background()
	id := appendFixtureEvent(t, f, 2, 1)
	events, e := f.s.ClaimEvents(ctx, f.reconciler, "expiring", 100, 300*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	ev, ok := findEvent(events, id)
	if !ok {
		t.Fatal("fixture event not claimed")
	}
	tx, e := f.p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT id FROM outbox_events WHERE id=$1 FOR UPDATE`, id); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- f.s.AckEvent(ctx, f.reconciler, id, ev.ClaimGeneration, "expiring") }()
	time.Sleep(400 * time.Millisecond)
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; !errors.Is(e, store.ErrConflict) {
		t.Fatalf("ack after lease expiry=%v", e)
	}
	events, e = f.s.ClaimEvents(ctx, f.reconciler, "replacement", 100, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	replacement, ok := findEvent(events, id)
	if !ok {
		t.Fatal("expired claim did not recover")
	}
	if replacement.ClaimGeneration <= ev.ClaimGeneration {
		t.Fatal("claim generation not increased")
	}
	if e = f.s.AckEvent(ctx, f.reconciler, id, replacement.ClaimGeneration, "replacement"); e != nil {
		t.Fatal(e)
	}
}
