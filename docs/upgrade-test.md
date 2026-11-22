# Upgrade test

The `upgrade (production)` job in `.github/workflows/ci.yml` runs `.cloud/scripts/tests/fresh-install/production.sh` with `UPGRADE_FROM=latest` (ADR 0018). It:

1. installs the newest `CodeClarityCE/deployment` release that has a `docker-compose.yaml` asset, and creates the operator account;
2. seeds data through the API, never the database (`seed_upgrade_data` in `.cloud/scripts/tests/fresh-install/seed.sh`): a project from an uploaded npm archive, a completed Default Analyzer analysis of it, and a ticket on both;
3. records what the API shows of them: the project, the analysis with its steps, SBOM and licences, and the ticket;
4. upgrades to the images built from the submodule pointers, runs the fresh-install checks and the analysis journey again, and fails unless the API shows the seeded project, analysis and ticket exactly as before (`check_seeded_data`), after the upgrade and after the second `up -d`.
5. once every check passed, writes the operator's login to `UPGRADE_JOURNEY_ENV` and leaves the stack up; the job's next step runs the frontend's `@upgrade` journey (`e2e/real-stack/upgrade.journey.mts`, golden journey 5), which logs in in the browser and fails unless the seeded project's results (SBOM and licences) and the seeded ticket are still shown. A failure keeps its Playwright trace as the `upgrade-journey` artifact.

`sh .cloud/scripts/tests/upgrade-seed.test.sh` tests the seeding and the comparison against a stand-in API, including a deleted ticket, emptied fields and dropped analysis results.

## Showing that a destructive migration fails the job

The job only runs on a real stack in CI, so this is done on a throwaway pull request, never merged:

1. In the `api` submodule, on a throwaway branch off the pointer, add `src/migrations/codeclarity/1899999999999-DropSeededTicket.ts`:

   ```ts
   import { MigrationInterface, QueryRunner } from "typeorm";

   // Deliberate breakage for the upgrade test: deletes the ticket it seeds.
   export class DropSeededTicket1899999999999 implements MigrationInterface {
     name = "DropSeededTicket1899999999999";

     public async up(queryRunner: QueryRunner): Promise<void> {
       await queryRunner.query(
         `DELETE FROM "ticket" WHERE "title" = 'Upgrade seed ticket'`,
       );
     }

     public async down(): Promise<void> {}
   }
   ```

2. Push that branch, point the umbrella's `api` submodule at it on a throwaway umbrella branch, and open a draft pull request to `develop`.
3. The `upgrade (production)` job fails with `FAIL upgrade from <tag>: the seeded ticket is intact`, followed by the diff of the ticket before and after. The project and analysis checks still pass.
4. Close the pull request and delete both branches.

To show a dropped analysis result instead, delete the seeded analysis's results (`DELETE FROM "result" WHERE "analysisId" IN (SELECT "id" FROM "analysis" WHERE "projectId" IN (SELECT "id" FROM "project" WHERE "name" = 'upgrade-seed-app'))`); the analysis check then fails.
