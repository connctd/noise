VERSION 						?= $(shell git describe --tags --always --dirty)
GIT_COMMIT          ?= $(shell git rev-list -1 HEAD)
RELEASE_VERSION			= $(shell git describe --abbrev=0 --tag)

GO_BUILD_ENV_VARS						?= GO111MODULE=on 
GO_BUILD_ENV_TEST_VARS			?= GO111MODULE=on

GO_BUILD_FLAGS 							= -tags=smolcert

GO_TEST 				?= $(GO_BUILD_ENV_TEST_VARS) go test $(GO_BUILD_FLAGS) -race -covermode=atomic -coverprofile=single.coverprofile

.PHONY: test clean

clean:
	rm -f *.coverprofile

test:
	$(GO_TEST)