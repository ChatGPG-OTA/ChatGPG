import time
import segno
from io import BytesIO
from PIL import Image

def qr_animate(display, text, chunk_size=800, frame_delay=1.0):
    """
    Displays long text as multiple QR frames (animated).
    Works on:
      • ST7789 LCD (display.image)
      • Desktop terminal (ASCII QR)
    """
    import segno
    from io import BytesIO
    from PIL import Image
    import time

    chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]
    total = len(chunks)
    print(f"[QR Animate] Showing {total} frame(s)...")

    for i, chunk in enumerate(chunks, start=1):
        payload = f"CHUNK:{i}/{total}\n{chunk}"
        qr = segno.make_qr(payload, error='q')

        # Generate image buffer
        img_buf = BytesIO()
        qr.save(img_buf, kind='png', scale=4)
        img_buf.seek(0)
        img = Image.open(img_buf)

        # Try LCD first
        shown = False
        if hasattr(display, "image"):
            try:
                display.image(img)
                shown = True
            except Exception as e:
                print(f"[WARN] display.image() failed: {e}")

        # Fallback: print QR to terminal
        if not shown:
            print("\n")
            print(qr.terminal(compact=True))
            print(f"[Frame {i}/{total}]")
            time.sleep(frame_delay)

    print("[QR Animate] Done.\n")
