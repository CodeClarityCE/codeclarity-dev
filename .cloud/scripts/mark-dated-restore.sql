-- Marks the knowledge database as a dated restore, called by restore-knowledge-dated.sh.
-- Old dumps predate the table, so create it here with the API migration's definition.
CREATE TABLE IF NOT EXISTS knowledge_dated_restore (
	id boolean PRIMARY KEY DEFAULT true CHECK (id),
	label character varying NOT NULL,
	marked_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO knowledge_dated_restore (label) VALUES (:'label')
	ON CONFLICT (id) DO UPDATE SET label = EXCLUDED.label, marked_at = now();
