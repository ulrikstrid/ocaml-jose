echo removing _coverage dir
rm -rf _coverage
rm junit.xml

echo patching dune file
gsed -i '$i \(preprocess (pps bisect_ppx))\' jose/dune

echo running tests
BISECT_ENABLE=yes REPORT_PATH=./junit.xml esy test --force

esy echo "#{self.target_dir / 'default' / 'test'}"

cp $(esy echo "#{self.target_dir / 'default' / 'test' / 'junit.xml'}") ./junit.xml

echo copying bisect files
cp $(esy echo "#{self.target_dir / 'default' / 'test'}")/[bisect]* ./

echo generating reports
esy bisect-ppx-report html
esy bisect-ppx-report summary

echo reseting files
git checkout jose/dune
rm bisect*
rm test.{exe,ml}
