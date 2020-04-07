#!/bin/bash

echo "TRAVIS_BRANCH=${TRAVIS_BRANCH}"
if [[ "${TRAVIS_BRANCH}" != "master" ]]; then
    echo "give up updating TOC @ branch ${TRAVIS_BRANCH}"
    exit 0
fi

git config --global user.email "travis@travis-ci.org"
git config --global user.name "Travis CI"

./tool/gh-md-toc --insert ./README.md

git add ./README.md
git commit --message "Travis build: $TRAVIS_BUILD_NUMBER"

git remote add origin https://${GH_TRAVIS_CI_TOKEN}@github.com/ytinirt/notes.git > /dev/null 2>&1
git push --quiet --set-upstream origin master
