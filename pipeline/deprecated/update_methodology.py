from pathlib import Path
import base64
import sys
import urllib.parse
import xml.etree.ElementTree as ET
import zlib


FILE_PATH = Path('documentation/methodology-v2.xml')


def decode_diagram(payload: str) -> str:
    raw = base64.b64decode(payload.strip())
    try:
        decoded = zlib.decompress(raw, -15).decode('utf-8')
    except zlib.error:
        decoded = zlib.decompress(raw).decode('utf-8')
    return urllib.parse.unquote(decoded)


def encode_diagram(xml_text: str) -> str:
    escaped = urllib.parse.quote(xml_text, safe='')
    compressor = zlib.compressobj(level=9, wbits=-15)
    compressed = compressor.compress(escaped.encode('utf-8')) + compressor.flush()
    payload = base64.b64encode(compressed).decode('ascii')
    return payload


def main() -> int:
    try:
        tree = ET.parse(FILE_PATH)
        root = tree.getroot()
        diagram = root.find('.//diagram')
        if diagram is None or not (diagram.text and diagram.text.strip()):
            print('Could not locate draw.io diagram payload in methodology-v2.xml')
            return 1

        xml_text = decode_diagram(diagram.text)

        replacements = {
            'value="Phase 1: Vulnerability ID &amp; Setup"': (
                'value="Phase 1: PoC Execution &amp; Verification"'
            ),
            'value="3. Replicate Vulnerability&#10;(Run PoC in Test Env)"': (
                'value="3. Execute PoC&#10;(Verify with explicit proof)"'
            ),
        }

        updated = xml_text
        changed = False
        for old, new in replacements.items():
            if old in updated:
                updated = updated.replace(old, new)
                changed = True

        if not changed:
            print('No matching Phase 1 labels found; rewriting payload with existing text.')

        diagram.text = encode_diagram(updated)
        tree.write(FILE_PATH, encoding='utf-8', xml_declaration=True)
        print('Updated methodology-v2.xml successfully.')
        return 0
    except Exception as e:
        print(f'Failed to update methodology: {e}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
