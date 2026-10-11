package escl

import "fmt"

// ScanSettings is the one scan the agent ever asks for: A4 from the feeder,
// both sides, colour, 300 dpi, JPEG.
//
// BlankPageDetectionAndRemoval is never sent. The HP ScanJet Pro N4000
// answers it with 409, and Sally needs the blank backs anyway: they are the
// markers that pair a back with its front.
func ScanSettings(version string) []byte {
	if !validVersion(version) {
		version = DefaultVersion
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<scan:ScanSettings xmlns:pwg="%s" xmlns:scan="%s">
  <pwg:Version>%s</pwg:Version>
  <scan:Intent>Document</scan:Intent>
  <pwg:ScanRegions>
    <pwg:ScanRegion>
      <pwg:Height>3508</pwg:Height>
      <pwg:Width>2480</pwg:Width>
      <pwg:XOffset>0</pwg:XOffset>
      <pwg:YOffset>0</pwg:YOffset>
      <pwg:ContentRegionUnits>escl:ThreeHundredthsOfInches</pwg:ContentRegionUnits>
    </pwg:ScanRegion>
  </pwg:ScanRegions>
  <pwg:InputSource>Feeder</pwg:InputSource>
  <scan:Duplex>true</scan:Duplex>
  <scan:ColorMode>RGB24</scan:ColorMode>
  <scan:XResolution>300</scan:XResolution>
  <scan:YResolution>300</scan:YResolution>
  <pwg:DocumentFormat>image/jpeg</pwg:DocumentFormat>
  <scan:DocumentFormatExt>image/jpeg</scan:DocumentFormatExt>
</scan:ScanSettings>
`, NSPWG, NSScan, version))
}
