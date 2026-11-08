-- The pin covered the whole cluster configuration as well as the vault key,
-- so any configuration change, including a new default in a release, stopped
-- every rollout until an operator cleared it. Only the vault key needs to
-- match across replicas. Clear the old pin; the migrator pins the vault key's
-- identity right after migrating.
UPDATE captured.settings SET compatibility_sha256 = NULL WHERE singleton;
