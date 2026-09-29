# Build, check and deploy Mercurio (its binary is foreman). `make build` is the default target.
# Scripts are always run through `bash <path>`; the repo ships no executable bits.

.PHONY: build test lint testdb-clean db-up migrate db-down images pause resume require-project

# A long-lived development database: postgres:17 on 127.0.0.1:$(DEV_DB_PORT), data in a named
# volume until `make db-down`. Its password is a fixed, loopback-only development value.
DEV_DB_PORT ?= 55432
DEV_DB_URL ?= postgres://postgres:foreman@127.0.0.1:$(DEV_DB_PORT)/foreman_dev?sslmode=disable
DEV_DB_CONTAINER := foreman-dev-postgres
DEV_DB_VOLUME := foreman-dev-pgdata

build:
	go build -o bin/foreman ./cmd/foreman

# The tests against a throwaway Postgres 17 in Docker (or DATABASE_URL's database, when set).
test:
	bash scripts/dev/testdb.sh

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
	bash -n scripts/dev/testdb.sh

# Remove every throwaway test database, including ones a hard-killed run left behind.
testdb-clean:
	docker ps -aq --filter label=mercurio-project.testdb | xargs -r docker rm -f -v

# Start the development database (or restart a stopped one) and wait until it accepts connections.
db-up:
	@docker start $(DEV_DB_CONTAINER) >/dev/null 2>&1 || \
	  docker run -d --name $(DEV_DB_CONTAINER) -e POSTGRES_PASSWORD=foreman -e POSTGRES_DB=foreman_dev \
	    -p 127.0.0.1:$(DEV_DB_PORT):5432 -v $(DEV_DB_VOLUME):/var/lib/postgresql/data postgres:17 >/dev/null
	@for i in $$(seq 60); do \
	  docker exec $(DEV_DB_CONTAINER) pg_isready -q -h 127.0.0.1 -U postgres -d foreman_dev && exit 0; sleep 1; \
	done; echo "db-up: the development database did not become ready" >&2; exit 1
	@echo "development database: $(DEV_DB_URL)"

# Apply pending migrations: to DATABASE_URL when it is set, otherwise to the development database.
migrate: build
	DATABASE_URL="$${DATABASE_URL:-$(DEV_DB_URL)}" ./bin/foreman migrate up

# Remove the development database and its data.
db-down:
	-docker rm -f -v $(DEV_DB_CONTAINER) >/dev/null 2>&1
	-docker volume rm $(DEV_DB_VOLUME) >/dev/null 2>&1

# The deployment: your Google Cloud project and region, the values in infra/terraform.tfvars.
#   make images PROJECT_ID=my-project REGION=us-central1
PROJECT_ID ?=
REGION ?= us-central1
IMAGE_REPO = $(REGION)-docker.pkg.dev/$(PROJECT_ID)/foreman
BUILDER = projects/$(PROJECT_ID)/serviceAccounts/builder@$(PROJECT_ID).iam.gserviceaccount.com

require-project:
	@test -n "$(PROJECT_ID)" || { echo "set PROJECT_ID, for example: make $(MAKECMDGOALS) PROJECT_ID=my-project" >&2; exit 1; }

# Build both images with Cloud Build from HEAD, a commit already on origin/main, push them to
# Artifact Registry, and write their digests into infra/images.auto.tfvars for Terraform. Only what
# the images need is sent, from `git archive` of HEAD, never the working tree, and the build's
# configuration is HEAD's too. The images are tagged with the commit (tags are immutable), so a
# commit already built is not built again. The build runs as the `builder` account (infra/) and
# stages the archive in <project>_cloudbuild, which Terraform creates.
images: require-project
	@git fetch --quiet origin main
	@git merge-base --is-ancestor HEAD origin/main || \
	  { echo "images: HEAD is not on origin/main; images are built only from landed commits" >&2; exit 1; }
	@set -e; tag=$$(git rev-parse --short=12 HEAD); \
	digest() { gcloud artifacts docker images describe "$(IMAGE_REPO)/$$1:$$tag" --project $(PROJECT_ID) \
	  --format='value(image_summary.digest)' 2>/dev/null; }; \
	if [ -n "$$(digest foreman)" ] && [ -n "$$(digest echo-runner)" ]; then \
	  echo "images: $$tag is already built"; \
	else \
	  src=$$(mktemp --suffix=.tgz); cfg=$$(mktemp --suffix=.yaml); trap 'rm -f "$$src" "$$cfg"' EXIT; \
	  git archive --format=tar.gz -o "$$src" HEAD go.mod go.sum Dockerfile cmd internal migrations; \
	  git show HEAD:cloudbuild.yaml > "$$cfg"; \
	  gcloud builds submit "$$src" --project $(PROJECT_ID) --config "$$cfg" --service-account $(BUILDER) \
	    --substitutions _REPO=$(IMAGE_REPO),_TAG=$$tag; \
	fi; \
	foreman=$$(digest foreman); runner=$$(digest echo-runner); \
	case "$$foreman$$runner" in sha256:*sha256:*) ;; *) echo "images: no digests for $$tag" >&2; exit 1;; esac; \
	printf '%s\n' "# Written by \`make images\` from commit $$tag: the images Terraform deploys, by digest." \
	  "foreman_image     = \"$(IMAGE_REPO)/foreman@$$foreman\"" \
	  "echo_runner_image = \"$(IMAGE_REPO)/echo-runner@$$runner\"" > infra/images.auto.tfvars; \
	cat infra/images.auto.tfvars

# Pause the deployment: the dispatcher's tick stops, then Cloud SQL stops, so the running costs do.
# Resume does the reverse: the database first, since the callback API pings it at start. Terraform
# ignores both states. Deploy only while resumed.
pause: require-project
	gcloud scheduler jobs pause dispatcher-tick --location $(REGION) --project $(PROJECT_ID)
	gcloud sql instances patch foreman --activation-policy NEVER --project $(PROJECT_ID) --quiet

resume: require-project
	gcloud sql instances patch foreman --activation-policy ALWAYS --project $(PROJECT_ID) --quiet
	gcloud scheduler jobs resume dispatcher-tick --location $(REGION) --project $(PROJECT_ID)
