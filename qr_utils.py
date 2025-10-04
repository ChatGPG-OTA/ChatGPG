import time
import segno
from io import BytesIO
from PIL import Image

def qr_animate(display, text, chunk_size=400, frame_delay=1.0):
    """
    Displays long text as multiple QR frames (animated).
    Works on:
      • ST7789 LCD (display.image)
      • Desktop terminal (ASCII QR)
    """
    import time, segno
    from PIL import Image
    from io import BytesIO
    import tempfile, os

    chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]
    total = len(chunks)
    print(f"[QR Animate] Showing {total} frame(s)...")

    gif_frames = []
    frame_size = (240, 240)  # consistent output (same as LCD)

    for i, chunk in enumerate(chunks, start=1):
        payload = f"CHUNK:{i}/{total}\n{chunk}"
        qr = segno.make_qr(payload, error='q')

        # Create image
        buf = BytesIO()
        qr.save(buf, kind="png", scale=8, border=1)  # consistent scale
        buf.seek(0)
        img = Image.open(buf).convert("RGB")

        # Normalize all frames to same size
        img = img.resize(frame_size, Image.NEAREST)

        shown = False
        try:
            if hasattr(display, "image"):
                display.image(img)
                shown = True
        except Exception as e:
            print(f"[WARN] display.image() failed: {e}")

        if not shown:
            print("\n\n")
            print(qr.terminal(compact=True))
            print(f"[Frame {i}/{total}]")
            time.sleep(frame_delay)

        gif_frames.append(img)

    print("[QR Animate] Done.\n")

    # # --- Optional GIF export (debug only) ---
    # try:
    #     os.makedirs("debug_gifs", exist_ok=True)
    #     tmp_path = os.path.join("debug_gifs", f"qr_debug_{int(time.time())}.gif")
    #     gif_frames[0].save(
    #         tmp_path,
    #         save_all=True,
    #         append_images=gif_frames[1:],
    #         duration=int(frame_delay * 1000),
    #         loop=0,
    #     )
    #     print(f"[DEBUG] Animation saved: {tmp_path}")
    # except Exception as e:
    #     print(f"[WARN] Could not save debug GIF: {e}")
