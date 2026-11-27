-- Each replica keeps its own copy of Undertext's Registry in memory and reads it
-- again when it needs to, so no replica reads or writes the shared copy.
DROP TABLE captured.registry;
