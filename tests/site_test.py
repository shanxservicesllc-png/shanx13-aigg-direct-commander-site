from pathlib import Path
import unittest,re
ROOT=Path(__file__).resolve().parents[1]
class SiteContract(unittest.TestCase):
 def test_files(self):
  for f in ('index.html','styles.css','site.js','favicon.svg'):
   self.assertTrue((ROOT/f).is_file(), f)
 def test_separate_domain(self):
  h=(ROOT/'index.html').read_text('utf-8')
  self.assertNotIn('shanxservices.com/',h)
  self.assertNotIn('shanxservices-site',h)
 def test_sections(self):
  h=(ROOT/'index.html').read_text('utf-8')
  for k in ('platform','capabilities','security','access','account'):
   self.assertIn('id="'+k+'"',h)
 def test_no_faked_live_metrics(self):
  h=(ROOT/'index.html').read_text('utf-8')
  for marker in ('NO LIVE DATA','Pricing not yet published','Checkout not enabled','AUTHENTICATED CUSTOMER PILOT LIVE'):
   self.assertIn(marker,h)
 def test_buttons_have_actions(self):
  h=(ROOT/'index.html').read_text('utf-8')
  self.assertIn('id="menuToggle"',h)
  self.assertIn('data-cap="usage"',h)
 def test_static_code_inert(self):
  js=(ROOT/'site.js').read_text('utf-8')
  for suspicious in ("eval(", "innerHTML", "fetch(", "localStorage", "document.cookie"):
   self.assertNotIn(suspicious,js)
if __name__ == '__main__': unittest.main()
