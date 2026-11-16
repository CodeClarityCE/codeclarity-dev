# The knowledge dump image, codeclarityce/knowledge-dump:<date>: the knowledge and config dumps
# with their manifest, on the stack's Postgres so it carries pg_restore. It runs the knowledge
# restore setup job by default. Build context: a directory holding dump/ and restore-dump.sh
# (see .github/workflows/knowledge-dump.yml). Keep the base equal to the stack's db image.
FROM postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873

COPY restore-dump.sh /usr/local/bin/restore-dump.sh
COPY dump/knowledge-manifest.json dump/knowledge-manifest.sha256 /dump/
COPY dump/config.dump /dump/
# Its own layer, the large one.
COPY dump/knowledge.dump /dump/

ENV DUMP_DIR=/dump
USER postgres
ENTRYPOINT ["sh", "/usr/local/bin/restore-dump.sh"]
CMD ["restore-if-empty"]
