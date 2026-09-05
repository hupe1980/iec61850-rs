#!/usr/bin/env bash
# Fetch the freely available reference documents used by this project into specs/ (git-ignored).
# Only public material is fetched: ITU-T Recommendations, RFCs, Wireshark ASN.1 modules (GPL-2,
# reference only), public preview/sample PDFs of IEC standards (front matter + TOC), the UCAIug
# 9-2LE guideline (via the Wayback Machine), a community mirror of the SCL XSD, and sample pcaps.
# Paid IEC/ISO standards and IEC code components (SCL XSD / NSD packages) must be obtained
# manually; see concepts/SPECS.md.
set -euo pipefail
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
mkdir -p specs/{osi-itu,rfc,asn1-wireshark,iec-previews,scl,pcap,ucaiug}

dl() { # url dest
  if [ -s "$2" ]; then echo "skip   $2"; return; fi
  if curl -fsSL --retry 3 --max-time 180 -A "$UA" -o "$2" "$1"; then echo "ok     $2"; else echo "FAILED $2 ($1)" >&2; rm -f "$2"; fi
}
itu() { dl "https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-$1!!PDF-E&type=items" "specs/osi-itu/$2"; }
rfc() { dl "https://www.rfc-editor.org/rfc/rfc$1.txt" "specs/rfc/rfc$1-$2.txt"; }
ws()  { dl "https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/$1" "specs/asn1-wireshark/$(basename "$1")"; }

# ITU-T OSI upper layers + ASN.1
itu X.214-199511-I X.214-transport-service.pdf
itu X.224-199511-I X.224-ISO8073-transport-protocol-COTP.pdf
itu X.215-199511-I X.215-session-service.pdf
itu X.225-199511-I X.225-ISO8327-session-protocol.pdf
itu X.216-199407-I X.216-presentation-service.pdf
itu X.226-199407-I X.226-ISO8823-presentation-protocol.pdf
itu X.217-199504-I X.217-ACSE-service.pdf
itu X.227-199504-I X.227-ISO8650-ACSE-protocol.pdf
itu X.680-202102-I X.680-ASN1-basic-notation.pdf
itu X.690-202102-I X.690-ASN1-BER-CER-DER.pdf
# RFCs
rfc 1006 ISO-transport-over-TCP-TPKT
rfc 905  ISO8073-transport-protocol
rfc 6407 GDOI-group-key-mgmt-62351-9
rfc 8052 GDOI-support-for-IEC62351
rfc 4330 SNTPv4
rfc 5905 NTPv4
rfc 5246 TLS1.2
rfc 8446 TLS1.3
rfc 3376 IGMPv3
# Wireshark ASN.1 modules and dissectors (GPL-2; reference/oracle only)
for f in asn1/mms/mms.asn asn1/mms/mms.cnf asn1/mms/packet-mms-template.c \
         asn1/goose/goose.asn asn1/goose/goose.cnf asn1/goose/packet-goose-template.c \
         asn1/sv/sv.asn asn1/sv/sv.cnf asn1/sv/packet-sv-template.c \
         asn1/acse/acse.asn asn1/pres/ISO8823-PRESENTATION.asn asn1/pres/ISO9576-PRESENTATION.asn \
         packet-ses.c packet-tpkt.c packet-ositp.c; do ws "$f"; done
# Public preview / sample PDFs (front matter + TOC only)
P=specs/iec-previews; I=https://cdn.standards.iteh.ai/samples
dl "$I/16230/d2b7e3585c4d435ba62f912e2b9ea603/IEC-61850-7-2-2010.pdf"                 $P/IEC-61850-7-2-Ed2.1-2020-preview.pdf
dl "$I/16341/1d1bdc2df9aa49a3a7192146daa3146c/IEC-61850-8-1-2011.pdf"                 $P/IEC-61850-8-1-Ed2.1-2020-preview.pdf
dl "$I/23452/baf1f49507d64dd4960ef151d66ebe00/IEC-61850-9-2-2011-AMD1-2020.pdf"       $P/IEC-61850-9-2-Amd1-2020-preview.pdf
dl "$I/14993/08d597c7f6674d34badb7d988e8b7d5d/IEC-61850-7-4-2010.pdf"                 $P/IEC-61850-7-4-Ed2.1-2020-preview.pdf
dl "$I/102471/8f0aeb2d2e5b4ed9888f68d8fc525f73/IEC-61850-7-1-2011-AMD1-2020.pdf"      $P/IEC-61850-7-1-Amd1-2020-preview.pdf
dl "$I/23369/430eac9d13514d34a5c2860b3346a5e3/IEC-61850-6-2009-AMD1-2018.pdf"         $P/IEC-61850-6-Amd1-2018-preview.pdf
dl "$I/117232/04085e0171f24f24a45d17e61b1aa8cf/IEC-61850-6-2009-AMD2-2024.pdf"        $P/IEC-61850-6-Amd2-2024-preview.pdf
dl "$I/iec/iec-61850-10-2012-amd1-2025/8d277fb9c1b940ea954e4c37706ea5ce/iec-61850-10-2012-amd1-2025.pdf" $P/IEC-61850-10-Amd1-2025-preview.pdf
dl "$I/22722/4873cff3eb8347ae9b7c9106b9d3b20c/IEC-IEEE-61850-9-3-2016.pdf"            $P/IEC-IEEE-61850-9-3-2016-PTP-preview.pdf
dl "$I/19401/78430474eaf34c0482b17f2f9c35ce06/IEC-TR-61850-90-5-2012.pdf"             $P/IEC-TR-61850-90-5-2012-preview.pdf
dl "$I/23767/55397774db5f4d6490ae6c898110cc25/IEC-TS-61850-7-7-2018.pdf"              $P/IEC-TS-61850-7-7-NSD-preview.pdf
dl "$I/102476/88f51459928e44f3b051832d08a7518a/IEC-62351-6-2020.pdf"                  $P/IEC-62351-6-2020-preview.pdf
dl "$I/22022/a85dae220aed4df7a3b97706f65a0dcf/IEC-62351-4-2018.pdf"                   $P/IEC-62351-4-2018-preview.pdf
dl "$I/105100/b7a344cdd98f47e4a67e4a94e9df50b5/IEC-62351-3-2023.pdf"                  $P/IEC-62351-3-2023-preview.pdf
dl "https://www.sis.se/api/document/preview/571807/"                                    $P/IEC-TR-61850-90-5-2012-preview-sis.pdf
dl "https://content.nettedautomation.com/n/download/2025/IEC61850-Series_KHS_2025-01-07.pdf" $P/IEC61850-Series-overview-KHS-2025-01-07.pdf
# UCAIug 9-2LE (the 2019/2020 Wayback snapshots are truncated at 1 MiB; 2016 is complete) + 90-5 thesis
dl "https://web.archive.org/web/2016id_/http://iec61850.ucaiug.org/Implementation%20Guidelines/DigIF_spec_9-2LE_R2-1_040707-CB.pdf" specs/ucaiug/IEC61850-9-2LE-DigIF_spec_R2-1.pdf
dl "https://sites.ecse.rpi.edu/~vanfrl/documents/mscthesis/2015_Seyed_Reza%20Firouzi_MSc%20thesis%20report.pdf" specs/ucaiug/RPI-2015-Firouzi-IEC61850-90-5-R-GOOSE-R-SV-thesis.pdf
# SCL XSD (community mirror of the IEC code component; prefer the official IEC package when available)
for f in SCL.xsd SCL_BaseTypes.xsd SCL_Enums.xsd SCL_IED.xsd SCL_Substation.xsd SCL_Communication.xsd SCL_DataTypeTemplates.xsd; do
  dl "https://raw.githubusercontent.com/rte-france/SCL_Loader/master/src/scl_loader/resources/SCL_Schema/$f" "specs/scl/$f"; done
# Sample captures
dl "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mms.pcap.gz" specs/pcap/mms.pcap.gz
# The MMS capture arrives gzipped; the tests read plain pcap, so unpack it beside the archive.
[ -f specs/pcap/mms.pcap.gz ] && gunzip -kf specs/pcap/mms.pcap.gz 2>/dev/null || true
dl "https://raw.githubusercontent.com/mdehus/goose-IEC61850-scapy/master/wireshark2.pcap"      specs/pcap/goose-mdehus.pcap
dl "https://raw.githubusercontent.com/mgadelha/Sampled_Values/master/SV_Normal_Traffic.cap"     specs/pcap/sv-9-2LE-normal-traffic.cap
dl "https://raw.githubusercontent.com/mgadelha/Sampled_Values/master/README.md"                 specs/pcap/sv-README.md

# OpenSCD test fixtures (Apache-2.0) — the first SCL round-trip corpus
mkdir -p specs/fixtures/openscd
curl -fsSL -A "$UA" "https://api.github.com/repos/openscd/open-scd/contents/packages/openscd/test/testfiles" \
  | python3 -c 'import sys,json;[print(x["name"],x["download_url"]) for x in json.load(sys.stdin) if x["type"]=="file"]' \
  | while read -r name url; do dl "$url" "specs/fixtures/openscd/$name"; done
echo
echo "Manual: IEC code components (SCL XSD 2007B4/2007C5, NSD) from https://www.iec.ch/tc57/supportdocuments -> specs/iec-code-components/"
echo "Manual: purchased standards -> specs/iec-purchased/"
