rm -rf coverage
gsed -i '$i \(preprocess (pps bisect_ppx))\' jose/dune

BISECT_ENABLE=yes esy test
esy bisect-ppx-report -html ./coverage bisect0001.out

git checkout jose/dune
rm bisect0001.out

open coverage/index.html
