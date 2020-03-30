echo removing _coverage dir
rm -rf _coverage
rm junit.xml

echo running tests
BISECT_ENABLE=yes REPORT_PATH=./junit.xml esy test --force

cp $(esy echo "#{self.target_dir / 'default' / 'test' / 'junit.xml'}") ./junit.xml

echo generating reports
esy bisect-ppx-report html
esy bisect-ppx-report summary
