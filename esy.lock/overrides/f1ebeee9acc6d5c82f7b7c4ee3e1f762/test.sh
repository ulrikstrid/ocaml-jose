#! /bin/bash

mkdir -p test_dir

cd ./test_dir

echo '{"name": "esy-fswatch-prebuilx","esy": {"buildsInSource": "unsafe","build": "EsyPrebuiltApp.exe -action export -target \"#{self.root / os}\" -package \"#{esy-fswatch-prebuilt.install}\""}, "dependencies": {"esy-fswatch-prebuilt" : "ulrikstrid/esy-fswatch:esy.json#'$(git rev-parse --short HEAD)'", "esy-prebuilt-util": "0.1.5"}}' > package.json

echo "ESY INSTALL"
esy install
echo "ESY BUILD"
esy build

esy b fswatch --help
esy which fswatch
