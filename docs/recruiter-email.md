Subject: Follow-up project — governed AI agent for security data

Hi [Name],

Thank you again for the conversation. I built a small follow-up project to demonstrate how I
would apply generative AI without giving a model unrestricted database access.

The demo turns security questions into answers backed by a versioned catalog of pre-approved SQL.
It uses local semantic embeddings for retrieval, applies catalog-defined role controls before
ranking, displays query sensitivity for audit context, and lets Claude select only a query ID
and validated parameters—not SQL. Execution uses
a separate PostgreSQL connection, bound parameters, hash verification, a read-only transaction,
a timeout, and a row cap. Every answer shows its query name, sensitivity, source commit, and
result evidence.

The repository includes a polished FastAPI UI, PostgreSQL/pgvector Docker environment, daily
catalog synchronization from the public source repository, and tests that run without Docker or
an API key.

AI agent: https://github.com/Lucas-Song-Dev/approved-sql-rag-agent  
Mock security-team source: https://github.com/Lucas-Song-Dev/security-vulnerability-api

I would be happy to walk through the threat model and the trade-offs behind the design.

Best,
Lucas
