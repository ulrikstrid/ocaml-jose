rm -rf _coverage
gsed -i '$i \(preprocess (pps bisect_ppx))\' jose/dune

BISECT_ENABLE=yes esy test
esy bisect-ppx-report html
esy bisect-ppx-report summary

git checkout jose/dune
rm bisect*
