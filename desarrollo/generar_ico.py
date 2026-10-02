"""
Genera traverso_forensics.ico desde traverso_logo.png
con todas las resoluciones requeridas por Windows.
"""
from PIL import Image
import struct, io, os, sys

SRC = "traverso_logo.png"
DST = "traverso_forensics.ico"
SIZES = [16, 24, 32, 48, 64, 128, 256]

def create_ico(img_rgba, sizes):
    images = []
    for s in sizes:
        resized = img_rgba.resize((s, s), Image.LANCZOS)
        buf = io.BytesIO()
        resized.save(buf, format='PNG')
        images.append((s, buf.getvalue()))

    num = len(images)
    header = struct.pack('<HHH', 0, 1, num)
    offset = 6 + num * 16
    entries = b''
    data = b''
    for s, png_bytes in images:
        w = h = s if s < 256 else 0
        entries += struct.pack('<BBBBHHII', w, h, 0, 0, 1, 32, len(png_bytes), offset)
        offset += len(png_bytes)
        data += png_bytes
    return header + entries + data

if not os.path.exists(SRC):
    print(f"ERROR: no se encontro {SRC}")
    sys.exit(1)

img = Image.open(SRC).convert('RGBA')
w, h = img.size
lado = max(w, h)
cuadrado = Image.new('RGBA', (lado, lado), (13, 27, 42, 255))
cuadrado.paste(img, ((lado - w) // 2, (lado - h) // 2))

ico_bytes = create_ico(cuadrado, SIZES)
with open(DST, 'wb') as f:
    f.write(ico_bytes)

print(f"ICO generado: {DST} ({len(ico_bytes)//1024} KB) — {len(SIZES)} resoluciones")
