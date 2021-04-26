#!/bin/sh

TAG="$1"

if [ -z "$TAG" ]; then
  printf "Usage: ./dune-release.sh <tag-name>\n"
  printf "Please make sure that dune-release is available.\n"
  exit 1
fi

step()
{
  printf "Continue? [Yn] "
  read action
  if [ "x$action" == "xn" ]; then exit 2; fi
  if [ "x$action" == "xN" ]; then exit 2; fi
}

dune-release tag "$TAG"
step
dune-release distrib -p jose -t "$TAG" --skip-tests #--skip-lint
step
dune-release publish distrib -p jose -t "$TAG"
step
dune-release opam pkg -p jose -t "$TAG"
step
dune-release opam submit -p jose -t "$TAG"
