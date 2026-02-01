-- 003_add_agent_actions.sql: agent_actions column on spans (Loop 18)

ALTER TABLE spans ADD COLUMN agent_actions TEXT NOT NULL DEFAULT '[]';
