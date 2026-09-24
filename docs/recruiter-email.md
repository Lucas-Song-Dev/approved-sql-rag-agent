Subject: BrainRidge FinTech AI Accelerator — Governed Agentic SQL & RAG Demo

Hi [Name],

Thank you again for the discussion. To demonstrate my hands-on approach to enterprise AI architecture and guardrails, I prepared a live FinTech AI Accelerator that directly addresses how financial institutions can safely deploy generative AI without giving models unrestricted database access.

The system answers enterprise security, compliance, and infrastructure questions using a versioned catalog of reviewed SQL. It uses local semantic embeddings (pgvector + FastEmbed) for retrieval, applies database-level RBAC pre-filtering before semantic ranking, and uses Claude Haiku via structured tool calling to select query IDs and strongly-typed parameters—never generating or executing unvetted SQL. Execution uses a dedicated read-only PostgreSQL transaction, planner cost/row budget checks (`EXPLAIN`), and a redacted immutable audit log.

The architecture includes a modern FastAPI UI, PostgreSQL/pgvector Docker environment, daily automated catalog synchronization, and a complete test suite.

Live Demo: http://[DROPLET_IP]:8000
AI Agent Repo: https://github.com/Lucas-Song-Dev/approved-sql-rag-agent
Financial System of Record: https://github.com/Lucas-Song-Dev/security-vulnerability-api

I would be excited to walk through the threat model, trade-offs, and how this accelerator can be leveraged for BrainRidge's banking and FinTech clients.

Best,
Lucas
