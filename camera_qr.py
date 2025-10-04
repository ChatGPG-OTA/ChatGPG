import sys
import time
import cv2
from pyzbar.pyzbar import decode

def scan_qr_chunks_continuous(camera_index=0, timeout=120):
    """
    Reads QR chunks continuously from a single webcam session.
    Handles multi-frame GIFs smoothly (no camera reopen).
    """
    print("Starting continuous QR scanner (press 'q' to cancel)...")

    cap = cv2.VideoCapture(camera_index)
    if not cap.isOpened():
        print("Cannot open webcam.")
        return None

    start_time = time.time()
    chunks = {}
    total = None
    last_seen = time.time()

    while time.time() - start_time < timeout:
        ret, frame = cap.read()
        if not ret:
            continue

        # Decode QR in frame
        qrs = decode(frame)
        for qr in qrs:
            data = qr.data.decode("utf-8", errors="ignore").strip()
            lines = data.splitlines()
            if not lines:
                continue

            header = lines[0]
            if header.startswith("CHUNK:"):
                try:
                    index, total_frames = map(int, header.split(":")[1].split("/"))
                    total = total_frames
                    body = "\n".join(lines[1:])
                    if index not in chunks:
                        chunks[index] = body
                        print(f"Got chunk {index}/{total}")
                        last_seen = time.time()
                except Exception:
                    print("Invalid CHUNK header:", header)
                    continue
            else:
                cap.release()
                cv2.destroyAllWindows()
                print("Single QR detected.")
                return data

        # Check completion
        if total and len(chunks) == total:
            cap.release()
            cv2.destroyAllWindows()
            print(f"All {total} chunks received successfully.")
            ordered = "".join(chunks[i] for i in range(1, total + 1))
            return ordered

        # Show live feed in one window
        status = f"{len(chunks)}/{total or '?'} chunks"
        cv2.putText(frame, status, (10, 30),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 0), 2)
        cv2.imshow("ChatGPG QR Scanner", frame)

        # Exit on 'q'
        if cv2.waitKey(1) & 0xFF == ord('q'):
            print("\n[INFO] User cancelled.")
            break

        # Timeout only if no new chunk in 15s
        if time.time() - last_seen > 15:
            print("\nTimeout — no new chunks detected.")
            break

    cap.release()
    cv2.destroyAllWindows()
    print("Incomplete transfer.")
    return None


# -------------------- ENTRY POINT --------------------
def scan_qr(settings):
    """
    Entry point for scanning a QR or multi-frame GIF.
    """
    source = settings.get("camera_source", "Desktop").lower()

    if source == "zerocam":
        try:
            from picamera2 import Picamera2
        except ImportError:
            print("picamera2 not available. Falling back to webcam.")
            return scan_qr_chunks_continuous()
        return scan_qr_zerocam_continuous()
    else:
        return scan_qr_chunks_continuous()


# -------------------- PI ZERO VARIANT --------------------
def scan_qr_zerocam_continuous(timeout=120):
    """
    Continuous QR scanner for Pi Zero camera (same behavior as webcam).
    """
    try:
        from picamera2 import Picamera2
    except ImportError:
        print("picamera2 not installed.")
        return None

    print("[INFO] Starting continuous Pi Zero QR scanner...")
    cam = Picamera2()
    cam.configure(cam.create_preview_configuration(main={"format": "XRGB8888", "size": (640, 480)}))
    cam.start()

    start_time = time.time()
    chunks = {}
    total = None
    last_seen = time.time()

    while time.time() - start_time < timeout:
        frame = cam.capture_array()
        qrs = decode(frame)

        for qr in qrs:
            data = qr.data.decode("utf-8", errors="ignore").strip()
            lines = data.splitlines()
            if not lines:
                continue

            header = lines[0]
            if header.startswith("CHUNK:"):
                try:
                    index, total_frames = map(int, header.split(":")[1].split("/"))
                    total = total_frames
                    body = "\n".join(lines[1:])
                    if index not in chunks:
                        chunks[index] = body
                        print(f"Got chunk {index}/{total}")
                        last_seen = time.time()
                except Exception:
                    print("Invalid CHUNK header:", header)
                    continue
            else:
                cam.stop()
                print("Single QR detected.")
                return data

        # Done?
        if total and len(chunks) == total:
            cam.stop()
            print(f"All {total} chunks received successfully.")
            ordered = "".join(chunks[i] for i in range(1, total + 1))
            return ordered

        if time.time() - last_seen > 15:
            print("\nTimeout — no new chunks detected.")
            break

        time.sleep(0.05)

    cam.stop()
    print("Incomplete transfer.")
    return None
