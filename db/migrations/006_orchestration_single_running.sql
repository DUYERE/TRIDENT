-- [01] One running orchestration task per principal, enforced by the database.
-- The engine mutex only guards one console process; two consoles sharing this
-- database could otherwise drive two tasks for the same principal at once.
-- The constraint sits on 'running' (not 'created'), so a create that never
-- starts cannot block the next task forever.
CREATE UNIQUE INDEX orchestration_tasks_one_running
 ON orchestration_tasks(owner_id)
 WHERE state = 'running';
