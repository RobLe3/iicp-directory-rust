-- #630 — preserve the SDK-advertised local backend flavour for parity with the
-- PHP reference directory. Informational only: no MeshLLM topology or peer data.
ALTER TABLE nodes ADD COLUMN backend VARCHAR(32) NULL AFTER sdk_version;
