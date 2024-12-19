#!/bin/sh

TAG="$1"

if [ -z "$TAG" ]; then
  printf "Usage: ./dune-release.sh <tag-name>\n"
  printf "Please make sure that dune-release is available.\n"
  exit 1
fi

step()
{
  local step_name="$1"
  echo "Next step is $step_name"
  printf "Continue? [Yn] "
  read action
  if [ "$action" = "n" ]; then exit 2; fi
  if [ "$action" = "N" ]; then exit 2; fi
}

dune-release tag "$TAG"
step "distrib"
dune-release distrib -p jose -t "$TAG" --skip-tests #--skip-lint
step "publish distrib"
dune-release publish distrib -p jose -t "$TAG"
step "opam pkg"
dune-release opam pkg -p jose -t "$TAG"
step "opam submit"
dune-release opam submit -p jose -t "$TAG"
