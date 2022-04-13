#!/bin/bash

TOOL_DIR=$(dirname $0)
DOCS_DIR="${TOOL_DIR}/../docs"

for doc in $(find ${DOCS_DIR} -name "*.md"); do
    ${TOOL_DIR}/gh-md-toc --insert ${doc}
done
