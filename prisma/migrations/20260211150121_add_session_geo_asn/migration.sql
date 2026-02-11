ALTER TABLE "Session"
  ADD COLUMN "geoCountry" CHAR(2),
  ADD COLUMN "asn" INTEGER,
  ADD COLUMN "asOrgHash" VARCHAR(64);

CREATE INDEX IF NOT EXISTS "Session_geoCountry_asn_idx"
  ON "Session" ("geoCountry", "asn");
